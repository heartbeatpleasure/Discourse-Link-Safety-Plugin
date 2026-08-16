# frozen_string_literal: true

require "time"

module ::LinkSafety
  module Providers
    class GoogleWebRisk < Base
      PROVIDER = "web_risk_lookup".freeze
      ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search".freeze
      THREAT_TYPES = %w[MALWARE SOCIAL_ENGINEERING UNWANTED_SOFTWARE].freeze

      def configured?
        SiteSetting.link_safety_google_api_key.present? &&
          SiteSetting.link_safety_google_user_protection_notice_acknowledged
      end

      def check_many(canonical_urls, deadline: nil)
        return configuration_errors(canonical_urls) unless configured?
        return {} if canonical_urls.empty?

        deadline ||= validation_deadline
        canonical_urls.to_h do |item|
          if deadline_expired?(deadline)
            [item.fingerprint, budget_exceeded_response]
          else
            [item.fingerprint, check_one(item, deadline: deadline)]
          end
        end
      end

      private

      def check_one(item, deadline:)
        params = [["uri", item.canonical]]
        THREAT_TYPES.each { |type| params << ["threatTypes", type] }
        uri = URI("#{ENDPOINT}?#{URI.encode_www_form(params)}")

        ::LinkSafety::Statistics.bump!(PROVIDER, provider_calls: 1)
        raw = request(
          uri,
          headers: { "X-Goog-Api-Key" => SiteSetting.link_safety_google_api_key },
          deadline: deadline,
        )
        if raw.length == 3
          _response, _latency, error = raw
          return error_response(error)
        end
        response, latency = raw
        ::LinkSafety::Statistics.bump!(PROVIDER, latency_total_ms: latency, latency_samples: 1)
        unless response.is_a?(Net::HTTPSuccess)
          return error_response("http_#{response.code}", latency)
        end
        payload = parse_json(response)
        return error_response(:malformed_response, latency) unless payload.is_a?(Hash)

        threat = payload["threat"]
        return error_response(:malformed_response, latency) if threat && !threat.is_a?(Hash)

        raw_types = Array(threat && threat["threatTypes"]).map(&:to_s)
        unknown_types = raw_types - THREAT_TYPES
        return error_response(:unsupported_threat_type, latency) if unknown_types.any?

        types = raw_types & THREAT_TYPES
        if threat.is_a?(Hash) && raw_types.empty?
          return error_response(:malformed_response, latency)
        end

        now = Time.zone.now
        expires_at =
          if types.any?
            # Web Risk defines expireTime as the positive-cache lifetime for a
            # matching ThreatUri. Do not invent a local lifetime when Google
            # omitted or malformed it: a warning/block must be backed by a
            # currently valid provider response.
            return error_response(:malformed_response, latency) if threat["expireTime"].blank?
            parsed_expiry = parse_expiry(threat["expireTime"])
            return error_response(:malformed_response, latency) unless parsed_expiry
            return error_response(:stale_provider_response, latency) if parsed_expiry <= now
            parsed_expiry
          else
            # The Lookup API defines positive caching through ThreatUri#expireTime
            # but does not provide a negative-cache lifetime for an empty {}
            # response. Do not invent one: re-check clean URLs on their next
            # uncached use so newly listed threats are not hidden behind a local
            # false-negative cache. LookupBudget limits API-cost abuse.
            now
          end

        ::LinkSafety::CircuitBreaker.record_success(PROVIDER)
        ::LinkSafety::HealthRegistry.success!(provider: PROVIDER, latency_ms: latency)
        Providers::Base::Response.new(status: types.any? ? "threat" : "clean", threat_types: types, expires_at: expires_at, error_code: nil, latency_ms: latency, provider_calls: 1)
      end

      def budget_exceeded_response
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: :validation_budget_exceeded)
        ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
        Providers::Base::Response.new(
          status: "error",
          threat_types: [],
          expires_at: Time.zone.now + 1.minute,
          error_code: "validation_budget_exceeded",
          latency_ms: nil,
          provider_calls: 0,
        )
      end

      def error_response(error, latency = nil)
        ::LinkSafety::CircuitBreaker.record_failure(PROVIDER) if transient_failure?(error)
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: error, latency_ms: latency)
        ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
        Providers::Base::Response.new(status: "error", threat_types: [], expires_at: Time.zone.now + 1.minute, error_code: error.to_s, latency_ms: latency, provider_calls: 0)
      end

      def configuration_errors(items)
        code =
          if SiteSetting.link_safety_google_api_key.blank?
            :missing_api_key
          else
            :google_user_protection_notice_not_acknowledged
          end
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: code)
        items.to_h do |item|
          [item.fingerprint, Providers::Base::Response.new(status: "error", threat_types: [], expires_at: Time.zone.now + 5.minutes, error_code: code.to_s, latency_ms: nil, provider_calls: 0)]
        end
      end

      def parse_expiry(value)
        Time.iso8601(value.to_s).in_time_zone
      rescue ArgumentError, TypeError
        nil
      end
    end
  end
end
