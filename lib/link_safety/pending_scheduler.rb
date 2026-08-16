# frozen_string_literal: true

module ::LinkSafety
  class PendingScheduler
    def self.for_post(post)
      surface = post.topic&.private_message? ? :private_message : :public_post
      schedule(target_type: "Post", target_id: post.id, urls: ::LinkSafety::Extractor.from_post_raw(post.raw, post.topic_id), surface: surface)
    end

    def self.for_chat_message(message)
      is_dm = ::Chat::Channel.direct_channel_chatable_types.include?(message.chat_channel&.chatable_type)
      surface = is_dm ? :chat_dm : :chat_public
      schedule(target_type: "Chat::Message", target_id: message.id, urls: ::LinkSafety::Extractor.from_chat_message(message.message, user: message.user), surface: surface)
    end

    def self.schedule(target_type:, target_id:, urls:, surface:)
      pending = Array(urls).filter_map { |url| ::LinkSafety::Canonicalizer.call(url) }.any? do |item|
        entry = ::LinkSafety::CacheEntry.lookup(provider: SiteSetting.link_safety_provider, fingerprint: item.fingerprint)
        entry&.verdict == "error"
      end
      return unless pending
      Jobs.enqueue_in(1.minute, :link_safety_retry_target, target_type: target_type, target_id: target_id, surface: surface.to_s, attempt: 1)
    rescue => e
      Rails.logger.warn("[LinkSafety] pending schedule failed class=#{e.class.name}")
    end
  end
end
