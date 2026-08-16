# frozen_string_literal: true

require "base64"
require "digest"

module ::LinkSafety
  module Providers
    class GoogleSafeBrowsingV5 < Base
      PROVIDER = "safe_browsing_v5".freeze
      ENDPOINT = "https://safebrowsing.googleapis.com/v5/hashes:search".freeze

      THREAT_TYPES = {
        1 => "MALWARE",
        2 => "SOCIAL_ENGINEERING",
        3 => "UNWANTED_SOFTWARE",
        4 => "POTENTIALLY_HARMFUL_APPLICATION",
      }.freeze

      # Every currently documented attribute makes the detail unsuitable for
      # ordinary navigation enforcement:
      #   0 = THREAT_ATTRIBUTE_UNSPECIFIED -> disregard the detail
      #   1 = CANARY                       -> do not enforce
      #   2 = FRAME_ONLY                   -> enforce only on frames
      # Unknown future attributes also cause the enclosing detail to be ignored,
      # as required by the Safe Browsing v5 forward-compatibility contract.
      KNOWN_NON_ENFORCEABLE_ATTRIBUTES = [0, 1, 2].freeze

      ParsedPayload = Data.define(:full_hashes, :cache_duration)

      def configured?
        SiteSetting.link_safety_google_api_key.present? &&
          SiteSetting.link_safety_safe_browsing_noncommercial_acknowledged &&
          SiteSetting.link_safety_google_user_protection_notice_acknowledged
      end

      def check_many(canonical_urls, deadline: nil)
        return configuration_errors(canonical_urls) unless configured?
        return {} if canonical_urls.empty?

        deadline ||= validation_deadline
        digest_maps = {}
        prefix_sets = {}
        invalid_results = {}

        canonical_urls.each do |item|
          begin
            expressions = ::LinkSafety::Canonicalizer.safe_browsing_expressions!(item.canonical)
            digests = expressions.map { |expression| Digest::SHA256.digest(expression) }.uniq
            raise ::LinkSafety::Canonicalizer::CanonicalizationError, :canonicalization_failure if digests.empty?

            digest_maps[item.fingerprint] = digests
            prefix_sets[item.fingerprint] = digests.map { |digest| digest.byteslice(0, 4) }.uniq
          rescue ::LinkSafety::Canonicalizer::CanonicalizationError => e
            invalid_results[item.fingerprint] = build_error_response(e.code)
          rescue StandardError => e
            Rails.logger.warn("[LinkSafety] Safe Browsing expression generation failed class=#{e.class.name}")
            ::LinkSafety::HealthRegistry.control_failure!(component: :canonicalizer, code: e.class.name)
            invalid_results[item.fingerprint] = build_error_response(:canonicalization_failure)
          end
        end

        valid_items = canonical_urls.reject { |item| invalid_results.key?(item.fingerprint) }
        chunks = []
        current = []
        current_count = 0
        valid_items.each do |item|
          count = prefix_sets[item.fingerprint].length
          if current.any? && current_count + count > 1000
            chunks << current
            current = []
            current_count = 0
          end
          current << item
          current_count += count
        end
        chunks << current if current.any?

        results = invalid_results
        chunks.each do |items|
          if deadline_expired?(deadline)
            results.merge!(error_results(items, :validation_budget_exceeded))
            next
          end
          response_results = request_chunk(items, prefix_sets, digest_maps, deadline: deadline)
          results.merge!(response_results)
        end
        results
      end

      private

      def request_chunk(items, prefix_sets, digest_maps, deadline:)
        prefixes = items.flat_map { |item| prefix_sets[item.fingerprint] }.uniq
        return error_results(items, :canonicalization_failure) if prefixes.empty?

        uri = build_search_uri(prefixes)
        ::LinkSafety::Statistics.bump!(PROVIDER, provider_calls: 1)
        raw = request(
          uri,
          headers: {
            "Accept" => "application/x-protobuf",
            "X-Goog-Api-Key" => SiteSetting.link_safety_google_api_key,
          },
          deadline: deadline,
        )
        if raw.length == 3
          _response, _latency, error = raw
          return error_results(items, error)
        end
        response, latency = raw
        ::LinkSafety::Statistics.bump!(PROVIDER, latency_total_ms: latency, latency_samples: 1)

        unless response.is_a?(Net::HTTPSuccess)
          return error_results(items, "http_#{response.code}", latency)
        end

        payload = parse_response_payload(response)
        unless payload
          log_malformed_response(response, reason: "unreadable_payload")
          return error_results(items, :malformed_response, latency)
        end

        duration = payload.cache_duration
        unless duration.is_a?(Numeric) && duration >= 0
          log_malformed_response(response, reason: "missing_or_invalid_cache_duration")
          return error_results(items, :malformed_response, latency)
        end

        expires_at = Time.zone.now + duration.seconds
        matches = Hash.new { |h, k| h[k] = [] }

        payload.full_hashes.each do |entry|
          full_hash = entry[:full_hash]
          next unless full_hash&.bytesize == 32

          details = enforceable_threat_names(entry[:details])
          next if details.empty?

          items.each do |item|
            matches[item.fingerprint].concat(details) if digest_maps[item.fingerprint].include?(full_hash)
          end
        end

        ::LinkSafety::CircuitBreaker.record_success(PROVIDER)
        ::LinkSafety::HealthRegistry.success!(provider: PROVIDER, latency_ms: latency)
        items.to_h do |item|
          threats = matches[item.fingerprint].uniq
          status = threats.any? ? "threat" : "clean"
          effective_expiry =
            if threats.any?
              # Safe Browsing ToS requires fresh Google data within 30 minutes
              # before warning/blocking on a Google-list verdict.
              [expires_at, 30.minutes.from_now].min
            else
              # The v5 protocol allows clients to extend negative caching only
              # up to 24 hours. Capping even a server-supplied anomalous value
              # avoids a stale clean verdict becoming a long-lived bypass.
              [expires_at, 24.hours.from_now].min
            end
          [item.fingerprint, build_response(status, threats, effective_expiry, latency)]
        end
      rescue ProtobufDecodeError, ArgumentError, RangeError, TypeError => e
        Rails.logger.warn("[LinkSafety] Safe Browsing response decode failed class=#{e.class.name}")
        error_results(items, :malformed_response, latency)
      end


      def enforceable_threat_names(details)
        Array(details).filter_map do |detail|
          threat_name = THREAT_TYPES[detail[:threat_type]]
          attributes = Array(detail[:attributes])

          # Unknown threat types and unknown attributes invalidate this detail.
          next unless threat_name
          next unless attributes.all? { |attribute| KNOWN_NON_ENFORCEABLE_ATTRIBUTES.include?(attribute) }
          next if attributes.any?

          threat_name
        end.uniq
      end

      def build_search_uri(prefixes)
        params = prefixes.map { |prefix| ["hashPrefixes", Base64.strict_encode64(prefix)] }
        URI("#{ENDPOINT}?#{URI.encode_www_form(params)}")
      end

      def parse_response_payload(response)
        body = response.body.to_s.b
        return if body.bytesize > Providers::Base::MAX_RESPONSE_BYTES

        content_type = response["Content-Type"].to_s.downcase
        if content_type.include?("json")
          parse_json_payload(response)
        else
          parse_protobuf_payload(body)
        end
      end

      # Keep JSON parsing as a compatibility path in case an intermediary or a
      # future endpoint representation legitimately returns the documented JSON
      # form. The normal v5 hashes:search response observed from the direct HTTP
      # endpoint is application/x-protobuf.
      def parse_json_payload(response)
        payload = parse_json(response)
        return unless payload.is_a?(Hash)

        duration = parse_duration(payload["cacheDuration"])
        return if duration.nil?

        full_hashes = Array(payload["fullHashes"]).filter_map do |entry|
          next unless entry.is_a?(Hash)
          full_hash = decode_bytes(entry["fullHash"])
          next unless full_hash&.bytesize == 32

          details = Array(entry["fullHashDetails"]).filter_map do |detail|
            next unless detail.is_a?(Hash)
            threat_type = threat_type_number(detail["threatType"])
            attributes = Array(detail["attributes"]).filter_map { |attribute| threat_attribute_number(attribute) }
            # If any JSON attribute was unknown, disregard the entire detail.
            next if Array(detail["attributes"]).length != attributes.length
            next unless threat_type
            { threat_type: threat_type, attributes: attributes }
          end

          { full_hash: full_hash, details: details }
        end

        ParsedPayload.new(full_hashes: full_hashes, cache_duration: duration)
      end

      def parse_protobuf_payload(body)
        full_hashes = []
        cache_duration = nil

        ProtobufReader.new(body).each_field do |field_number, wire_type, value|
          case field_number
          when 1
            raise ProtobufDecodeError, "full_hashes wire type" unless wire_type == 2
            full_hashes << parse_protobuf_full_hash(value)
          when 2
            raise ProtobufDecodeError, "cache_duration wire type" unless wire_type == 2
            cache_duration = parse_protobuf_duration(value)
          end
        end

        return if cache_duration.nil?
        ParsedPayload.new(full_hashes: full_hashes.compact, cache_duration: cache_duration)
      end

      def parse_protobuf_full_hash(bytes)
        full_hash = nil
        details = []

        ProtobufReader.new(bytes).each_field do |field_number, wire_type, value|
          case field_number
          when 1
            raise ProtobufDecodeError, "full_hash wire type" unless wire_type == 2
            full_hash = value.b
          when 2
            raise ProtobufDecodeError, "full_hash_details wire type" unless wire_type == 2
            detail = parse_protobuf_full_hash_detail(value)
            details << detail if detail
          end
        end

        return unless full_hash&.bytesize == 32
        { full_hash: full_hash, details: details }
      end

      def parse_protobuf_full_hash_detail(bytes)
        threat_type = nil
        attributes = []
        unknown_attribute = false

        ProtobufReader.new(bytes).each_field do |field_number, wire_type, value|
          case field_number
          when 1
            raise ProtobufDecodeError, "threat_type wire type" unless wire_type == 0
            threat_type = value
          when 2
            case wire_type
            when 0
              attributes << value
            when 2
              ProtobufReader.new(value).each_packed_varint { |attribute| attributes << attribute }
            else
              raise ProtobufDecodeError, "attributes wire type"
            end
          end
        end

        return unless THREAT_TYPES.key?(threat_type)
        unknown_attribute = attributes.any? { |attribute| !KNOWN_NON_ENFORCEABLE_ATTRIBUTES.include?(attribute) }
        return if unknown_attribute

        { threat_type: threat_type, attributes: attributes }
      end

      def parse_protobuf_duration(bytes)
        seconds = 0
        nanos = 0

        ProtobufReader.new(bytes).each_field do |field_number, wire_type, value|
          case field_number
          when 1
            raise ProtobufDecodeError, "duration seconds wire type" unless wire_type == 0
            seconds = value
          when 2
            raise ProtobufDecodeError, "duration nanos wire type" unless wire_type == 0
            nanos = value
          end
        end

        # Cache durations are expected to be non-negative. Values encoded as
        # negative protobuf int64/int32 appear as very large unsigned varints in
        # this minimal decoder and are rejected by these bounds as well.
        return if seconds.negative? || seconds > 315_576_000_000
        return if nanos.negative? || nanos >= 1_000_000_000

        seconds.to_f + (nanos.to_f / 1_000_000_000)
      end

      def threat_type_number(value)
        {
          "MALWARE" => 1,
          "SOCIAL_ENGINEERING" => 2,
          "UNWANTED_SOFTWARE" => 3,
          "POTENTIALLY_HARMFUL_APPLICATION" => 4,
        }[value.to_s]
      end

      def threat_attribute_number(value)
        {
          "THREAT_ATTRIBUTE_UNSPECIFIED" => 0,
          "CANARY" => 1,
          "FRAME_ONLY" => 2,
        }[value.to_s]
      end

      def log_malformed_response(response, reason:)
        content_type = response["Content-Type"].to_s.split(";", 2).first
        body_bytes = response.body.to_s.bytesize
        Rails.logger.warn(
          "[LinkSafety] Safe Browsing malformed response reason=#{reason} content_type=#{content_type.presence || 'unknown'} body_bytes=#{body_bytes}",
        )
      rescue StandardError
        # Diagnostics must never interfere with the fail-safe provider result.
        nil
      end

      def parse_duration(value)
        match = value.to_s.match(/\A(\d+(?:\.\d{1,9})?)s\z/)
        match ? match[1].to_f : nil
      end

      def decode_bytes(value)
        encoded = value.to_s
        return if encoded.blank?

        padded = encoded + ("=" * ((4 - encoded.length % 4) % 4))
        Base64.urlsafe_decode64(padded)
      rescue ArgumentError
        begin
          Base64.strict_decode64(padded)
        rescue ArgumentError
          nil
        end
      end

      def build_response(status, threats, expires_at, latency)
        Providers::Base::Response.new(
          status: status,
          threat_types: threats,
          expires_at: expires_at,
          error_code: nil,
          latency_ms: latency,
          provider_calls: 1,
        )
      end

      def error_results(items, error, latency = nil)
        ::LinkSafety::CircuitBreaker.record_failure(PROVIDER) if transient_failure?(error)
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: error, latency_ms: latency)
        ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
        expires_at = Time.zone.now + 1.minute
        items.to_h { |item| [item.fingerprint, build_error_response(error, latency, expires_at: expires_at)] }
      end

      def build_error_response(error, latency = nil, expires_at: Time.zone.now + 1.minute)
        Providers::Base::Response.new(
          status: "error",
          threat_types: [],
          expires_at: expires_at,
          error_code: error.to_s,
          latency_ms: latency,
          provider_calls: 0,
        )
      end

      def configuration_errors(items)
        code =
          if SiteSetting.link_safety_google_api_key.blank?
            :missing_api_key
          elsif !SiteSetting.link_safety_safe_browsing_noncommercial_acknowledged
            :safe_browsing_usage_not_acknowledged
          else
            :google_user_protection_notice_not_acknowledged
          end
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: code)
        items.to_h do |item|
          [item.fingerprint, Providers::Base::Response.new(status: "error", threat_types: [], expires_at: Time.zone.now + 5.minutes, error_code: code.to_s, latency_ms: nil, provider_calls: 0)]
        end
      end

      class ProtobufDecodeError < StandardError; end

      # Minimal protobuf wire reader for the Safe Browsing v5 response schema.
      # It deliberately supports only generic wire decoding and has no dependency
      # on google-protobuf, keeping plugin installation self-contained.
      class ProtobufReader
        MAX_VARINT_BYTES = 10

        def initialize(data)
          @data = data.to_s.b
          @offset = 0
        end

        def each_field
          return enum_for(:each_field) unless block_given?

          until eof?
            key = read_varint
            field_number = key >> 3
            wire_type = key & 0x07
            raise ProtobufDecodeError, "invalid field number" if field_number.zero?

            value = read_wire_value(wire_type)
            yield field_number, wire_type, value
          end
        end

        def each_packed_varint
          return enum_for(:each_packed_varint) unless block_given?
          yield read_varint until eof?
        end

        private

        def eof?
          @offset >= @data.bytesize
        end

        def read_varint
          value = 0
          shift = 0

          MAX_VARINT_BYTES.times do
            raise ProtobufDecodeError, "truncated varint" if eof?
            byte = @data.getbyte(@offset)
            @offset += 1
            value |= (byte & 0x7f) << shift
            return value if (byte & 0x80).zero?
            shift += 7
          end

          raise ProtobufDecodeError, "oversized varint"
        end

        def read_wire_value(wire_type)
          case wire_type
          when 0
            read_varint
          when 1
            read_fixed(8)
          when 2
            length = read_varint
            raise ProtobufDecodeError, "length exceeds message" if length > remaining
            value = @data.byteslice(@offset, length)
            @offset += length
            value
          when 5
            read_fixed(4)
          else
            # Groups (wire types 3/4) are obsolete and are not part of the v5
            # schema. Refuse them rather than attempting ambiguous recovery.
            raise ProtobufDecodeError, "unsupported wire type #{wire_type}"
          end
        end

        def read_fixed(length)
          raise ProtobufDecodeError, "truncated fixed field" if length > remaining
          value = @data.byteslice(@offset, length)
          @offset += length
          value
        end

        def remaining
          @data.bytesize - @offset
        end
      end
    end
  end
end
