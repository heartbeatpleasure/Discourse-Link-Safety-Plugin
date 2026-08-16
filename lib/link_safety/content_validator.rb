# frozen_string_literal: true

module ::LinkSafety
  class ContentValidator
    def self.validate_model!(model:, urls:, surface:, user:, failure_policy: nil)
      ::LinkSafety::DetectionRecorder.clear_queued!(model)

      _value, capture = ::LinkSafety::Statistics.capture do
        validate_model_without_statistics_capture!(
          model: model,
          urls: urls,
          surface: surface,
          user: user,
          failure_policy: failure_policy,
        )
      end

      blocked_entries = ::LinkSafety::DetectionRecorder.take_queued!(model)
      resolution = ::LinkSafety::Statistics.finalize_capture!(
        model,
        capture,
        on_rollback: -> {
          ::LinkSafety::DetectionRecorder.flush_entries!(blocked_entries, target: model)
        },
      )

      # Direct validation outside an Active Record persistence transaction is
      # uncommon in production but is supported: counters are written
      # immediately, and a blocked attempt must not disappear merely because
      # there is no transaction callback to receive it.
      if resolution == :immediate && blocked_entries.present?
        ::LinkSafety::DetectionRecorder.flush_entries!(blocked_entries, target: model)
      end
      nil
    end

    def self.validate_model_without_statistics_capture!(model:, urls:, surface:, user:, failure_policy: nil)
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
          threats.each do |result|
            ::LinkSafety::DetectionRecorder.queue_blocked!(
              model: model,
              result: result,
              surface: surface,
              user: user,
            )
          end
          model.errors.add(:base, I18n.t("link_safety.errors.malicious_link"))
          return
        else
          threats.each do |result|
            ::LinkSafety::DetectionRecorder.record!(
              result: result,
              surface: surface,
              user: user,
              action: :monitor_only,
            )
          end
        end
      end

      return if errors.empty?

      effective_failure_policy = (failure_policy || SiteSetting.link_safety_failure_policy).to_s
      if effective_failure_policy == "fail_closed"
        message = errors.any? do |result|
          %w[missing_api_key safe_browsing_usage_not_acknowledged].include?(result.error_code.to_s)
        end ? "link_safety.errors.configuration" : "link_safety.errors.unavailable"
        model.errors.add(:base, I18n.t(message))
      else
        ::LinkSafety::Statistics.bump!(SiteSetting.link_safety_provider, fail_open: 1)
      end
    end
    private_class_method :validate_model_without_statistics_capture!
  end
end
