# frozen_string_literal: true

module ::LinkSafety
  class FinalContentVerifier
    Result = Data.define(:checked, :threats, :errors)
    SCHEDULE_TTL = 15.minutes.to_i

    def self.schedule(target, delay: 1.minute, revalidation: false)
      return unless target&.id && SiteSetting.link_safety_enabled

      content_hash = ::LinkSafety::RetryContext.content_hash_for(target)
      content_version = ::LinkSafety::RetryContext.content_version_for(target)
      key = schedule_key(target, content_hash: content_hash, content_version: content_version)
      ttl = [delay.to_i + SCHEDULE_TTL, SCHEDULE_TTL].max
      return unless Discourse.redis.set(key, "1", nx: true, ex: ttl)

      Jobs.enqueue_in(
        delay,
        :link_safety_verify_rendered_target,
        target_type: target.class.name,
        target_id: target.id,
        attempt: 1,
        revalidation: !!revalidation,
        content_hash: content_hash,
        content_version: content_version,
      )
    rescue StandardError => e
      Discourse.redis.del(key) if defined?(key) && key.present?
      Rails.logger.warn("[LinkSafety] final verification schedule failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :final_verifier, code: e.class.name)
    end

    def self.verify!(target, revalidation: false)
      expected_hash = ::LinkSafety::RetryContext.content_hash_for(target)
      expected_version = ::LinkSafety::RetryContext.content_version_for(target)
      context = ::LinkSafety::TargetContext.for(target)
      return Result.new(checked: 0, threats: [], errors: []) unless context
      return Result.new(checked: 0, threats: [], errors: []) unless ::LinkSafety::SurfacePolicy.enabled?(context.surface)
      return Result.new(checked: 0, threats: [], errors: []) if context.extraction&.error_code.present?

      urls = Array(context.extraction&.urls)
      cooked = target.respond_to?(:cooked) ? target.cooked : nil
      final_extraction = ::LinkSafety::Extractor.final_document_result(cooked)
      return Result.new(checked: 0, threats: [], errors: []) if final_extraction.error_code.present?
      urls.concat(final_extraction.urls)
      urls = ::LinkSafety::UrlCandidateClassifier.filter(urls).uniq

      due_urls, previous = due_urls(urls, revalidation: revalidation)
      return Result.new(checked: 0, threats: [], errors: []) if due_urls.empty?

      results = ::LinkSafety::Checker.check_many(
        due_urls,
        surface: context.surface,
        force: true,
        user: context.actor,
        private_content: context.private_content,
        priority: :security,
      )
      unless ::LinkSafety::RetryContext.reload_matches_content?(
        target,
        expected_hash,
        expected_version: expected_version,
      )
        return Result.new(checked: results.length, threats: [], errors: [])
      end

      threats = results.select(&:threat?)
      errors = results.select(&:error?)
      clean = results.select(&:clean?)

      action = SiteSetting.link_safety_mode.to_s == "enforce" ? :disabled_after_publish : :monitor_only
      threats.each do |result|
        next if previous[result.fingerprint] == "threat"
        ::LinkSafety::DetectionRecorder.record!(
          result: result,
          surface: context.surface,
          user: context.actor,
          action: action,
          target: target,
        )
      end

      # A one-shot allowance lets Web Risk's documented zero-TTL clean result
      # restore the exact current content once without inventing a reusable
      # negative cache entry.
      ::LinkSafety::FinalContentGuard.allow_once!(target, clean.map(&:fingerprint)) if clean.any?

      transition = results.any? do |result|
        old = previous[result.fingerprint]
        (result.threat? && old != "threat") || (result.clean? && old == "threat") ||
          (result.clean? && old.nil?)
      end
      rebake(target) if transition && SiteSetting.link_safety_mode.to_s == "enforce"

      Result.new(checked: results.length, threats: threats, errors: errors)
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] final verification failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :final_verifier, code: e.class.name)
      Result.new(checked: 0, threats: [], errors: [])
    end


    def self.schedule_threat_refresh(target, threats)
      earliest_expiry = Array(threats).filter_map(&:expires_at).min
      return unless earliest_expiry && target&.id

      # Refresh shortly before the provider-backed threat expires. The verify
      # job is explicitly marked as revalidation so a still-valid cache entry
      # does not suppress the fresh provider check.
      delay_seconds = [(earliest_expiry - Time.zone.now - 60.seconds).to_i, 60].max
      delay_seconds = [delay_seconds, 24.hours.to_i].min
      schedule(target, delay: delay_seconds.seconds, revalidation: true)
    end

    def self.release_schedule(target, content_hash: nil, content_version: nil)
      return unless target&.id

      content_hash ||= ::LinkSafety::RetryContext.content_hash_for(target)
      content_version = ::LinkSafety::RetryContext.content_version_for(target) if content_version.nil?
      Discourse.redis.del(
        schedule_key(target, content_hash: content_hash, content_version: content_version),
      )
    rescue StandardError
      nil
    end

    def self.due_urls(urls, revalidation:)
      cutoff = SiteSetting.link_safety_revalidation_interval_hours.to_i.hours.ago
      previous = {}
      due = []

      Array(urls).each do |url|
        item = ::LinkSafety::Canonicalizer.call(url)
        next unless item
        next if ::LinkSafety::TrustedDomains.trusted?(item.host)

        entry = ::LinkSafety::CacheEntry.lookup_any(
          provider: SiteSetting.link_safety_provider,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        previous[item.fingerprint] = entry&.verdict

        should_check =
          if revalidation
            entry.nil? || entry.expires_at.blank? || entry.expires_at <= Time.zone.now ||
              entry.checked_at.blank? || entry.checked_at <= cutoff
          else
            valid = ::LinkSafety::CacheEntry.lookup(
              provider: SiteSetting.link_safety_provider,
              fingerprint: item.fingerprint,
              legacy_fingerprint: item.legacy_fingerprint,
            )
            valid.nil? ||
              (valid.verdict == "error" && ::LinkSafety::VerificationPolicy.retryable?(valid.error_code))
          end
        due << url if should_check
      end

      [due.uniq, previous]
    end
    private_class_method :due_urls

    def self.rebake(target)
      if target.is_a?(::Post)
        target.rebake!(invalidate_oneboxes: true)
      elsif defined?(::Chat::Message) && target.is_a?(::Chat::Message)
        target.rebake!(invalidate_oneboxes: true, skip_notifications: true)
      end
    end
    private_class_method :rebake

    def self.schedule_key(target, content_hash:, content_version:)
      ::LinkSafety::RedisNamespace.key(
        "final_verify",
        target.class.name,
        target.id,
        content_hash,
        content_version,
      )
    end
    private_class_method :schedule_key
  end
end
