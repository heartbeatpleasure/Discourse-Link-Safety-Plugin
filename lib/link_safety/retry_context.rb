# frozen_string_literal: true

require "digest"

module ::LinkSafety
  # Carries only immutable identifiers required for asynchronous work. A digest
  # binds a delayed verification to the exact current content. Posts also carry
  # the revision number so an edit which happens to restore identical raw text
  # cannot revive an older actor hint.
  class RetryContext
    def self.content_hash(content)
      Digest::SHA256.hexdigest(content.to_s)
    end

    def self.content_hash_for(target)
      case target
      when ::Post
        content_hash(target.raw)
      when ::UserProfile
        content_hash(join_fields(target.website, target.bio_raw))
      when ::Topic
        content_hash(target.featured_link)
      when ::Group
        content_hash(target.bio_raw)
      else
        if defined?(::Chat::Message) && target.is_a?(::Chat::Message)
          content_hash(target.message)
        end
      end
    end

    def self.content_version_for(target)
      if target.is_a?(::Post) && target.respond_to?(:version)
        return target.version
      end

      if target.respond_to?(:updated_at) && target.updated_at.present?
        return target.updated_at.utc.iso8601(6)
      end

      nil
    rescue StandardError
      nil
    end

    def self.matches_content?(target, expected_hash, expected_version: nil)
      # Compatibility with jobs queued by an older plugin version.
      return true if expected_hash.blank? && expected_version.blank?

      if expected_hash.present?
        current_hash = content_hash_for(target)
        return false unless current_hash.present? && current_hash == expected_hash.to_s
      end

      if expected_version.present?
        current_version = content_version_for(target)
        return false unless current_version.present? && current_version.to_s == expected_version.to_s
      end

      true
    end

    def self.reload_matches_content?(target, expected_hash, expected_version: nil)
      return false unless target&.persisted?

      target.reload
      matches_content?(target, expected_hash, expected_version: expected_version)
    rescue ActiveRecord::RecordNotFound
      false
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] retry content reload failed class=#{e.class.name}")
      false
    end

    def self.actor_for(target, actor_id: nil, expected_hash: nil, expected_version: nil)
      if actor_id.present? && expected_hash.present? &&
           matches_content?(target, expected_hash, expected_version: expected_version)
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

    def self.join_fields(*values)
      values.map { |value| value.to_s.b }.join("\0")
    end
    private_class_method :join_fields
  end
end
