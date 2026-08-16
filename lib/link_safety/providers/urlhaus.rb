# frozen_string_literal: true

module ::LinkSafety
  module Providers
    class Urlhaus < Base
      PROVIDER = "urlhaus".freeze
      ENDPOINT = URI("https://urlhaus-api.abuse.ch/v1/url/")

      def configured? = SiteSetting.link_safety_urlhaus_enabled && SiteSetting.link_safety_urlhaus_auth_key.present?

      def check(item, deadline: nil)
        return nil unless configured?

        body = URI.encode_www_form(url: item.canonical)
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
          ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: error)
          ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
          return nil
        end

        response, latency = raw
        ::LinkSafety::Statistics.bump!(PROVIDER, latency_total_ms: latency, latency_samples: 1)
        unless response.is_a?(Net::HTTPSuccess)
          ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: "http_#{response.code}", latency_ms: latency)
          ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
          return nil
        end

        payload = parse_json(response)
        unless payload.is_a?(Hash)
          ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: :malformed_response, latency_ms: latency)
          ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
          return nil
        end

        ::LinkSafety::HealthRegistry.success!(provider: PROVIDER, latency_ms: latency)
        payload["query_status"].to_s == "ok" ? "MALWARE_DISTRIBUTION" : nil
      rescue => e
        ::LinkSafety::HealthRegistry.failure!(provider: PROVIDER, code: e.class.name)
        ::LinkSafety::Statistics.bump!(PROVIDER, errors: 1)
        nil
      end
    end
  end
end
