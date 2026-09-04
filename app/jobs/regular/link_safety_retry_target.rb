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
      return unless ::LinkSafety::RetryContext.matches_content?(
        target,
        args[:content_hash],
        expected_version: args[:content_version],
      )

      # Jobs queued before 1.3.1 do not carry immutable content identity.
      # Snapshot the content at execution time so even those legacy jobs cannot
      # apply a provider response to content edited while the request is in flight.
      guard_hash = args[:content_hash].presence || ::LinkSafety::RetryContext.content_hash_for(target)
      guard_version =
        args[:content_version].presence || ::LinkSafety::RetryContext.content_version_for(target)

      context = ::LinkSafety::TargetContext.for(
        target,
        actor_id: args[:actor_id],
        expected_hash: guard_hash,
        expected_version: guard_version,
      )
      return unless context
      return unless context.surface == surface
      return if context.extraction.error_code.present? || context.extraction.urls.empty?

      previous_verdicts = current_verdicts(context.extraction.urls)
      results = ::LinkSafety::Checker.check_many(
        context.extraction.urls,
        surface: surface,
        force: true,
        bypass_circuit: false,
        user: context.actor,
        private_content: context.private_content,
        priority: :security,
      )
      # Close the edit-during-provider-call race. The provider response may be
      # cached, but it must never be attributed to or rebake content that changed
      # while the remote request was in flight.
      return unless ::LinkSafety::RetryContext.reload_matches_content?(
        target,
        guard_hash,
        expected_version: guard_version,
      )

      threats = results.select(&:threat?)
      errors = results.select(&:error?)

      action = SiteSetting.link_safety_mode.to_s == "enforce" ? :disabled_after_publish : :monitor_only
      threats.each do |result|
        next if previous_verdicts[result.fingerprint] == "threat"
        ::LinkSafety::DetectionRecorder.record!(
          result: result,
          surface: surface,
          user: context.actor,
          action: action,
          target: target,
        )
      end

      # Web Risk clean Lookup responses deliberately have no reusable negative
      # cache lifetime. Bridge exactly this verified content through its next
      # rebake so OneboxGate/FinalContentGuard do not immediately classify the
      # same fresh-clean URL as unknown again.
      clean_fingerprints = results.select(&:clean?).map(&:fingerprint)
      ::LinkSafety::FinalContentGuard.allow_once!(target, clean_fingerprints) if clean_fingerprints.any?

      # In Enforce this applies/clears blocked or unverified presentation. In
      # Monitor it also restores a link that may have been cooked while Enforce
      # was previously active.
      rebake(target) if threats.any? || clean_fingerprints.any?

      retryable_errors = errors.select { |result| ::LinkSafety::VerificationPolicy.retryable?(result.error_code) }
      attempt = args[:attempt].to_i
      if retryable_errors.any? && attempt < MAX_ATTEMPTS
        Jobs.enqueue_in(
          [attempt * 2, 10].min.minutes,
          :link_safety_retry_target,
          target_type: args[:target_type],
          target_id: args[:target_id],
          surface: args[:surface],
          attempt: attempt + 1,
          actor_id: args[:actor_id],
          content_hash: guard_hash,
          content_version: guard_version,
        )
      elsif threats.any?
        schedule_threat_refresh(target: target, surface: surface, results: threats, actor: context.actor)
      end
    end

    private

    def current_verdicts(urls)
      candidates = ::LinkSafety::UrlCandidateClassifier.filter(urls)
      candidates.filter_map { |url| ::LinkSafety::Canonicalizer.call(url) }.to_h do |item|
        entry = ::LinkSafety::CacheEntry.lookup(
          provider: SiteSetting.link_safety_provider,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        [item.fingerprint, entry&.verdict]
      end
    end

    def schedule_threat_refresh(target:, surface:, results:, actor:)
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
        actor_id: actor&.id,
        content_hash: ::LinkSafety::RetryContext.content_hash_for(target),
        content_version: ::LinkSafety::RetryContext.content_version_for(target),
      )
    end

    def find_target(type, id)
      case type.to_s
      when "Post" then ::Post.find_by(id: id)
      when "PostLocalization" then defined?(::PostLocalization) ? ::PostLocalization.find_by(id: id) : nil
      when "Chat::Message" then defined?(::Chat::Message) ? ::Chat::Message.find_by(id: id) : nil
      end
    end

    def rebake(target)
      if target.is_a?(::Post)
        target.rebake!(invalidate_oneboxes: true)
      elsif defined?(::PostLocalization) && target.is_a?(::PostLocalization)
        Jobs.enqueue(:process_localized_cooked, post_localization_id: target.id, recook: true)
      elsif defined?(::Chat::Message) && target.is_a?(::Chat::Message)
        target.rebake!(invalidate_oneboxes: true, skip_notifications: true)
      end
    end
  end
end
