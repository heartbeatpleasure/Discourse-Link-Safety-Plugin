# frozen_string_literal: true

module ::LinkSafety
  class PendingScheduler
    def self.for_post(post)
      context = ::LinkSafety::TargetContext.for(post)
      return unless context && ::LinkSafety::SurfacePolicy.enabled?(context.surface)
      return if context.extraction.error_code.present?

      schedule(
        target_type: "Post",
        target_id: post.id,
        urls: context.extraction.urls,
        surface: context.surface,
        actor_id: context.actor&.id,
        content_hash: ::LinkSafety::RetryContext.content_hash_for(post),
        content_version: ::LinkSafety::RetryContext.content_version_for(post),
      )
    end

    def self.for_post_localization(localization)
      context = ::LinkSafety::TargetContext.for(localization)
      return unless context && ::LinkSafety::SurfacePolicy.enabled?(context.surface)
      return if context.extraction.error_code.present?

      schedule(
        target_type: "PostLocalization",
        target_id: localization.id,
        urls: context.extraction.urls,
        surface: context.surface,
        actor_id: context.actor&.id,
        content_hash: ::LinkSafety::RetryContext.content_hash_for(localization),
        content_version: ::LinkSafety::RetryContext.content_version_for(localization),
      )
    end

    def self.for_chat_message(message)
      context = ::LinkSafety::TargetContext.for(message)
      return unless context && ::LinkSafety::SurfacePolicy.enabled?(context.surface)
      return if context.extraction.error_code.present?

      schedule(
        target_type: "Chat::Message",
        target_id: message.id,
        urls: context.extraction.urls,
        surface: context.surface,
        actor_id: context.actor&.id,
        content_hash: ::LinkSafety::RetryContext.content_hash_for(message),
        content_version: ::LinkSafety::RetryContext.content_version_for(message),
      )
    end

    def self.schedule(
      target_type:,
      target_id:,
      urls:,
      surface:,
      actor_id: nil,
      content_hash: nil,
      content_version: nil
    )
      return unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      candidates = ::LinkSafety::UrlCandidateClassifier.filter(urls)
      pending = candidates.filter_map { |url| ::LinkSafety::Canonicalizer.call(url) }.any? do |item|
        entry = ::LinkSafety::CacheEntry.lookup(
          provider: SiteSetting.link_safety_provider,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        entry&.verdict == "error" && ::LinkSafety::VerificationPolicy.retryable?(entry.error_code)
      end
      return unless pending

      Jobs.enqueue_in(
        1.minute,
        :link_safety_retry_target,
        target_type: target_type,
        target_id: target_id,
        surface: surface.to_s,
        attempt: 1,
        actor_id: actor_id,
        content_hash: content_hash,
        content_version: content_version,
      )
    rescue => e
      Rails.logger.warn("[LinkSafety] pending schedule failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :pending_scheduler, code: e.class.name)
    end
  end
end
