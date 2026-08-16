# frozen_string_literal: true

module ::Jobs
  class LinkSafetyRetryTarget < ::Jobs::Base
    MAX_ATTEMPTS = 5

    def execute(args)
      return unless SiteSetting.link_safety_enabled

      surface = args[:surface].to_s.to_sym
      return unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      target = find_target(args[:target_type], args[:target_id])
      return unless target

      extraction, user = target_extraction(target)
      return if extraction.error_code.present? || extraction.urls.empty?

      previous_verdicts = current_verdicts(extraction.urls)
      results = ::LinkSafety::Checker.check_many(
        extraction.urls,
        surface: surface,
        force: true,
        bypass_circuit: false,
      )
      threats = results.select(&:threat?)
      errors = results.select(&:error?)

      action = SiteSetting.link_safety_mode.to_s == "enforce" ? :disabled_after_publish : :monitor_only
      threats.each do |result|
        next if previous_verdicts[result.fingerprint] == "threat"
        ::LinkSafety::DetectionRecorder.record!(
          result: result,
          surface: surface,
          user: user,
          action: action,
          target: target,
        )
      end

      # A rebake is useful in both modes. In Enforce it applies/clears the
      # disabled-link presentation; after switching to Monitor it also restores
      # a link that may previously have been cooked while Enforce was active.
      rebake(target) if threats.any? || results.any?(&:clean?)

      attempt = args[:attempt].to_i
      if errors.any? && attempt < MAX_ATTEMPTS
        Jobs.enqueue_in(
          [attempt * 2, 10].min.minutes,
          :link_safety_retry_target,
          target_type: args[:target_type],
          target_id: args[:target_id],
          surface: args[:surface],
          attempt: attempt + 1,
        )
      elsif threats.any?
        schedule_threat_refresh(target: target, surface: surface, results: threats)
      end
    end

    private

    def current_verdicts(urls)
      Array(urls).filter_map { |url| ::LinkSafety::Canonicalizer.call(url) }.to_h do |item|
        entry = ::LinkSafety::CacheEntry.lookup(
          provider: SiteSetting.link_safety_provider,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        [item.fingerprint, entry&.verdict]
      end
    end

    def schedule_threat_refresh(target:, surface:, results:)
      return unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      earliest_expiry = results.filter_map(&:expires_at).min
      return unless earliest_expiry

      delay = [(earliest_expiry - Time.zone.now - 60.seconds).to_i, 60].max
      delay = [delay, 24.hours.to_i].min
      Jobs.enqueue_in(
        delay.seconds,
        :link_safety_retry_target,
        target_type: target.class.name,
        target_id: target.id,
        surface: surface.to_s,
        attempt: 1,
      )
    end

    def find_target(type, id)
      case type.to_s
      when "Post" then ::Post.find_by(id: id)
      when "Chat::Message" then defined?(::Chat::Message) ? ::Chat::Message.find_by(id: id) : nil
      end
    end

    def target_extraction(target)
      case target
      when ::Post
        [::LinkSafety::Extractor.post_raw_result(target.raw, target.topic_id), target.user]
      else
        [::LinkSafety::Extractor.chat_message_result(target.message, user: target.user), target.user]
      end
    end

    def rebake(target)
      if target.is_a?(::Post)
        target.rebake!(invalidate_oneboxes: true)
      elsif defined?(::Chat::Message) && target.is_a?(::Chat::Message)
        target.rebake!(invalidate_oneboxes: true, skip_notifications: true)
      end
    end
  end
end
