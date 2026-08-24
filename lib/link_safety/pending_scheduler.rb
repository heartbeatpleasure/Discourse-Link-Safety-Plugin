# frozen_string_literal: true

module ::LinkSafety
  class PendingScheduler
    def self.for_post(post)
      surface = post.topic&.private_message? ? :private_message : :public_post
      return unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      actor = ::LinkSafety::ActorResolver.for_post(post)
      extraction = ::LinkSafety::Extractor.post_raw_result(post.raw, post.topic_id, user: actor)
      return if extraction.error_code.present?

      schedule(
        target_type: "Post",
        target_id: post.id,
        urls: extraction.urls,
        surface: surface,
        actor_id: actor&.id,
        content_hash: ::LinkSafety::RetryContext.content_hash(post.raw),
      )
    end

    def self.for_chat_message(message)
      is_dm = ::Chat::Channel.direct_channel_chatable_types.include?(message.chat_channel&.chatable_type)
      surface = is_dm ? :chat_dm : :chat_public
      return unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      actor = ::LinkSafety::ActorResolver.for_chat_message(message)
      extraction = ::LinkSafety::Extractor.chat_message_result(
        message.message,
        user: actor,
        author_username: message.user&.username,
      )
      return if extraction.error_code.present?

      schedule(
        target_type: "Chat::Message",
        target_id: message.id,
        urls: extraction.urls,
        surface: surface,
        actor_id: actor&.id,
        content_hash: ::LinkSafety::RetryContext.content_hash(message.message),
      )
    end

    def self.schedule(target_type:, target_id:, urls:, surface:, actor_id: nil, content_hash: nil)
      return unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      candidates = ::LinkSafety::UrlCandidateClassifier.filter(urls)
      pending = candidates.filter_map { |url| ::LinkSafety::Canonicalizer.call(url) }.any? do |item|
        entry = ::LinkSafety::CacheEntry.lookup(provider: SiteSetting.link_safety_provider, fingerprint: item.fingerprint, legacy_fingerprint: item.legacy_fingerprint)
        entry&.verdict == "error"
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
      )
    rescue => e
      Rails.logger.warn("[LinkSafety] pending schedule failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :pending_scheduler, code: e.class.name)
    end
  end
end
