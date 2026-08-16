# frozen_string_literal: true

require "base64"
require "digest"

module ::LinkSafety
  module Providers
    class GoogleSafeBrowsingV5 < Base
      PROVIDER = "safe_browsing_v5".freeze
      ENDPOINT = "https://safebrowsing.googleapis.com/v5/hashes:search".freeze
      ENFORCEABLE_THREATS = %w[MALWARE SOCIAL_ENGINEERING UNWANTED_SOFTWARE POTENTIALLY_HARMFUL_APPLICATION].freeze
      KNOWN_ATTRIBUTES = %w[CANARY FRAME_ONLY THREAT_ATTRIBUTE_UNSPECIFIED].freeze
      NON_ENFORCEABLE_ATTRIBUTES = KNOWN_ATTRIBUTES.freeze

      def configured?
        SiteSetting.link_safety_google_api_key.present? && SiteSetting.link_safety_safe_browsing_noncommercial_acknowledged
      end

      def check_many(canonical_urls)
        return configuration_errors(canonical_urls) unless configured?
        return {} if canonical_urls.empty?

        digest_maps = {}
        prefix_sets = {}
        canonical_urls.each do |item|
          expressions = ::LinkSafety::Canonicalizer.safe_browsing_expressions(item.canonical)
          digests = expressions.map { |expression| Digest::SHA256.digest(expression) }.uniq
          digest_maps[item.fingerprint] = digests
          prefix_sets[item.fingerprint] = digests.map { |digest| digest.byteslice(0, 4) }.uniq
        end

        chunks = []
        current = []
        current_count = 0
        canonical_urls.each do |item|
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

        results = {}
        chunks.each do |items|
          response_results = request_chunk(items, prefix_sets, digest_maps)
          results.merge!(response_results)
        end
        results
      end

      private

      def request_chunk(items, prefix_sets, digest_maps)
        prefixes = items.flat_map { |item| prefix_sets[item.fingerprint] }.uniq
        params = prefixes.map { |prefix| ["hashPrefixes", Base64.strict_encode64(prefix)] }
        params << ["key", SiteSetting.link_safety_google_api_key]
        uri = URI("#{ENDPOINT}?#{URI.encode_www_form(params)}")

        raw = request(uri)
        if raw.length == 3
          _response, _latency, error = raw
          return error_results(items, error)
        end
        response, latency = raw
        ::LinkSafety::Statistics.bump!(PROVIDER, provider_calls: 1, latency_total_ms: latency, latency_samples: 1)

        unless response.is_a?(Net::HTTPSuccess)
          return error_results(items, "http_#{response.code}", latency)
        end

        payload = parse_json(response)
        return error_results(items, :malformed_response, latency) unless payload.is_a?(Hash)

        duration = parse_duration(payload["cacheDuration"])
        return error_results(items, :malformed_response, latency) if duration.nil?
        expires_at = Time.zone.now + duration.seconds
        full_hashes = Array(payload["fullHashes"])

        matches = Hash.new { |h, k| h[k] = [] }
        full_hashes.each do |entry|
          full_hash = decode_bytes(entry["fullHash"])
          next unless full_hash&.bytesize == 32
          details = Array(entry["fullHashDetails"]).filter_map do |detail|
            type = detail["threatType"].to_s
            attributes = Array(detail["attributes"]).map(&:to_s)
            next unless ENFORCEABLE_THREATS.include?(type)
            next if attributes.any? { |attribute| !KNOWN_ATTRIBUTES.include?(attribute) }
            next if (attributes & NON_ENFORCEABLE_ATTRIBUTES).any?
            type
          end.uniq
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
          effective_expiry = threats.any? ? [expires_at, 30.minutes.from_now].min : expires_at
          [item.fingerprint, build_response(status, threats, effective_expiry, latency)]
        end
      rescue ArgumentError
        error_results(items, :malformed_response)
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
        ::LinkSafety::CircuitBreaker.record_failure(PROVIDER)
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: error, latency_ms: latency)
        ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
        expires_at = Time.zone.now + 1.minute
        items.to_h do |item|
          [item.fingerprint, Providers::Base::Response.new(status: "error", threat_types: [], expires_at: expires_at, error_code: error.to_s, latency_ms: latency, provider_calls: 0)]
        end
      end

      def configuration_errors(items)
        code = SiteSetting.link_safety_google_api_key.blank? ? :missing_api_key : :safe_browsing_usage_not_acknowledged
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: code)
        items.to_h do |item|
          [item.fingerprint, Providers::Base::Response.new(status: "error", threat_types: [], expires_at: Time.zone.now + 5.minutes, error_code: code.to_s, latency_ms: nil, provider_calls: 0)]
        end
      end
    end
  end
end
