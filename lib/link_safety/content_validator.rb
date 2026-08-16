# frozen_string_literal: true

module ::LinkSafety
  class ContentValidator
    def self.validate_model!(model:, urls:, surface:, user:, failure_policy: nil)
      urls = Array(urls).compact.uniq
      return if urls.empty?

      canonical = urls.filter_map { |url| ::LinkSafety::Canonicalizer.call(url) }
      external = canonical.reject do |item|
        ::LinkSafety::TrustedDomains.local_host?(item.host) || ::LinkSafety::TrustedDomains.trusted?(item.host)
      end
      if external.length > SiteSetting.link_safety_max_external_urls_per_submission
        model.errors.add(:base, I18n.t("link_safety.errors.too_many_links"))
        return
      end

      results = ::LinkSafety::Checker.check_many(urls, surface: surface)
      threats = results.select(&:threat?)
      errors = results.select(&:error?)

      if threats.any?
        if SiteSetting.link_safety_mode == "enforce"
          threats.each { |result| ::LinkSafety::DetectionRecorder.record!(result: result, surface: surface, user: user, action: :blocked_before_save) }
          message_key =
            if threats.any? { |result| result.provider.to_s == "safe_browsing_v5" }
              "link_safety.errors.malicious_link_google"
            else
              "link_safety.errors.malicious_link"
            end
          model.errors.add(:base, I18n.t(message_key))
          return
        else
          threats.each { |result| ::LinkSafety::DetectionRecorder.record!(result: result, surface: surface, user: user, action: :monitor_only) }
        end
      end

      return if errors.empty?
      effective_failure_policy = (failure_policy || SiteSetting.link_safety_failure_policy).to_s
      if effective_failure_policy == "fail_closed"
        message = errors.any? { |r| %w[missing_api_key safe_browsing_usage_not_acknowledged].include?(r.error_code.to_s) } ? "link_safety.errors.configuration" : "link_safety.errors.unavailable"
        model.errors.add(:base, I18n.t(message))
      else
        ::LinkSafety::Statistics.bump!(SiteSetting.link_safety_provider, fail_open: 1)
      end
    end
  end
end
