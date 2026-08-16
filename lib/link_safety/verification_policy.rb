# frozen_string_literal: true

module ::LinkSafety
  class VerificationPolicy
    HARD_FAILURE_CODES = %w[
      canonicalization_failure
      excessive_percent_encoding
      invalid_url
      url_too_long
      extractor_failure
      validation_budget_exceeded
      missing_provider_result
      malformed_response
      provider_internal_error
      response_too_large
      missing_api_key
      safe_browsing_usage_not_acknowledged
      private_surface_lookup_disabled
      private_network_full_url_provider_disabled
    ].freeze

    TRANSIENT_HTTP_CODES = %w[http_408 http_425 http_429].freeze

    def self.hard_failure?(code)
      value = code.to_s
      return true if HARD_FAILURE_CODES.include?(value)
      return false if TRANSIENT_HTTP_CODES.include?(value)

      value.match?(/\Ahttp_[34]\d\d\z/)
    end

    def self.block_errors?(errors, failure_policy:)
      codes = Array(errors).map { |error| error.respond_to?(:error_code) ? error.error_code : error }.compact
      return true if SiteSetting.link_safety_mode.to_s == "enforce" && codes.any? { |code| hard_failure?(code) }

      failure_policy.to_s == "fail_closed"
    end

    def self.configuration_error?(code)
      value = code.to_s
      return true if %w[
        missing_api_key
        safe_browsing_usage_not_acknowledged
        private_surface_lookup_disabled
        private_network_full_url_provider_disabled
      ].include?(value)
      return false if TRANSIENT_HTTP_CODES.include?(value)

      value.match?(/\Ahttp_[34]\d\d\z/)
    end
  end
end
