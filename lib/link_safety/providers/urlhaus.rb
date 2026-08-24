# frozen_string_literal: true

module ::LinkSafety
  module Providers
    class Urlhaus < Base
      PROVIDER = "urlhaus".freeze
      ENDPOINT = URI("https://urlhaus-api.abuse.ch/v1/url/")
      POSITIVE_TTL = 12.hours
      NEGATIVE_TTL = 1.hour

      def enabled? = SiteSetting.link_safety_urlhaus_enabled
      def configured? = enabled? && SiteSetting.link_safety_urlhaus_auth_key.present?

      def check(item, deadline: nil, bypass_circuit: false)
        return configuration_error unless configured?
        return error_response(:circuit_open) if !bypass_circuit && ::LinkSafety::CircuitBreaker.open?(PROVIDER)

        body = URI.encode_www_form(url: item.full_url)
        ::LinkSafety::Statistics.bump!(PROVIDER, provider_calls: 1)
        raw = request(
          ENDPOINT,
          method: :post,
          headers: {
            "Auth-Key" => SiteSetting.link_safety_urlhaus_auth_key,
            "Content-Type" => "application/x-www-form-urlencoded",
            "Accept" => "application/json",
          },
          body: body,
          deadline: deadline,
        )

        if raw.length == 3
          _response, _latency, error = raw
          return error_response(error)
        end

        response, latency = raw
        ::LinkSafety::Statistics.bump!(PROVIDER, latency_total_ms: latency, latency_samples: 1)
        return error_response("http_#{response.code}", latency) unless response.is_a?(Net::HTTPSuccess)

        payload = parse_json(response)
        return error_response(:malformed_response, latency) unless payload.is_a?(Hash)

        case payload["query_status"].to_s
        when "no_results"
          success_response("clean", [], NEGATIVE_TTL.from_now, latency)
        when "ok"
          # URLhaus' URL lookup endpoint uses `ok` only for a known database
          # entry. Validate the malware classification when present instead of
          # treating arbitrary malformed `ok` responses as malicious/clean.
          threat = payload["threat"].to_s
          return error_response(:malformed_response, latency) if threat.blank?
          return error_response(:unsupported_threat_type, latency) unless threat == "malware_download"

          success_response("threat", ["MALWARE_DISTRIBUTION"], POSITIVE_TTL.from_now, latency)
        when "invalid_url"
          error_response(:invalid_url, latency)
        when "http_post_expected"
          error_response(:provider_internal_error, latency)
        else
          error_response(:malformed_response, latency)
        end
      rescue => e
        Rails.logger.warn("[LinkSafety] URLhaus request failed class=#{e.class.name}")
        error_response(:provider_internal_error)
      end

      private

      def success_response(status, threats, expires_at, latency)
        ::LinkSafety::CircuitBreaker.record_success(PROVIDER)
        ::LinkSafety::HealthRegistry.success!(provider: PROVIDER, latency_ms: latency)
        Providers::Base::Response.new(
          status: status,
          threat_types: threats,
          expires_at: expires_at,
          error_code: nil,
          latency_ms: latency,
          provider_calls: 1,
        )
      end

      def configuration_error
        error_response(:missing_urlhaus_auth_key, nil, transient: false, expires_at: 5.minutes.from_now)
      end

      def error_response(error, latency = nil, transient: nil, expires_at: 1.minute.from_now)
        is_transient = transient.nil? ? transient_failure?(error) : transient
        ::LinkSafety::CircuitBreaker.record_failure(PROVIDER) if is_transient
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: error, latency_ms: latency)
        ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
        Providers::Base::Response.new(
          status: "error",
          threat_types: [],
          expires_at: expires_at,
          error_code: error.to_s,
          latency_ms: latency,
          provider_calls: 0,
        )
      end
    end
  end
end
