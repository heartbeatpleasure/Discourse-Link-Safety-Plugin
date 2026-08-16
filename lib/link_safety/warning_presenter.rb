# frozen_string_literal: true

module ::LinkSafety
  # Keeps Google-required attribution limited to verdicts actually supplied by
  # a Google service. URLhaus-only detections deliberately remain provider
  # independent, matching Google's attribution restrictions.
  class WarningPresenter
    GOOGLE_PROVIDERS = %w[safe_browsing_v5 web_risk_lookup].freeze
    SAFE_BROWSING_ADVISORY = "https://developers.google.com/safe-browsing/v4/advisory".freeze
    WEB_RISK_ADVISORY = "https://docs.cloud.google.com/web-risk/docs/advisory".freeze

    def self.google_provider?(provider)
      GOOGLE_PROVIDERS.include?(provider.to_s)
    end

    def self.advisory_url(provider)
      provider.to_s == "web_risk_lookup" ? WEB_RISK_ADVISORY : SAFE_BROWSING_ADVISORY
    end

    def self.validation_message(results)
      google_result = Array(results).find { |result| google_provider?(result.provider) }
      return I18n.t("link_safety.errors.malicious_link") unless google_result

      validation_message_for_provider(google_result.provider)
    end

    def self.validation_message_for_provider(provider)
      return I18n.t("link_safety.errors.malicious_link") unless google_provider?(provider)

      I18n.t(
        "link_safety.errors.malicious_link_google",
        advisory_url: advisory_url(provider),
      )
    end

    def self.rendered_warning(provider)
      return { google: false, text: I18n.t("link_safety.rendered_warning") } unless google_provider?(provider)

      {
        google: true,
        text: I18n.t("link_safety.rendered_warning_google"),
        advisory_label: I18n.t("link_safety.google_advisory_label"),
        advisory_url: advisory_url(provider),
        accuracy_notice: I18n.t("link_safety.google_accuracy_notice"),
      }
    end
  end
end
