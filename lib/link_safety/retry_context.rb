# frozen_string_literal: true

require "digest"

module ::LinkSafety
  # Carries only the minimum immutable context required for an asynchronous
  # retry. The content digest prevents a delayed job from applying a verdict or
  # actor hint to content that has been edited since the job was scheduled.
  class RetryContext
    def self.content_hash(content)
      Digest::SHA256.hexdigest(content.to_s)
    end

    def self.content_hash_for(target)
      case target
      when ::Post
        content_hash(target.raw)
      else
        if defined?(::Chat::Message) && target.is_a?(::Chat::Message)
          content_hash(target.message)
        end
      end
    end

    def self.matches_content?(target, expected_hash)
      return true if expected_hash.blank? # Compatibility with jobs queued before this version.

      current_hash = content_hash_for(target)
      current_hash.present? && current_hash == expected_hash.to_s
    end

    def self.actor_for(target, actor_id: nil, expected_hash: nil)
      if actor_id.present? && expected_hash.present? && matches_content?(target, expected_hash)
        # If the scheduled actor was deleted in the meantime, keep attribution
        # empty rather than falling back to the content owner.
        return ::User.find_by(id: actor_id)
      end

      case target
      when ::Post
        ::LinkSafety::ActorResolver.for_post(target)
      else
        if defined?(::Chat::Message) && target.is_a?(::Chat::Message)
          ::LinkSafety::ActorResolver.for_chat_message(target)
        end
      end
    end
  end
end
