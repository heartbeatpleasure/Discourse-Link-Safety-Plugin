# frozen_string_literal: true

module ::LinkSafety
  # Resolve the user who supplied the content being checked. This avoids
  # charging lookup budgets, detections and optional User Notes to an original
  # author when Discourse records a different acting user or last editor.
  class ActorResolver
    def self.for_post(post)
      return unless post

      owner = post.user
      acting_user = post.acting_user if post.respond_to?(:acting_user)

      # Post#acting_user falls back to the owner when no explicit acting user
      # was supplied. Only give it priority when Discourse actually recorded a
      # different actor; a reloaded edited post relies on persisted last_editor.
      return acting_user if acting_user.present? && acting_user != owner

      post.last_editor || acting_user || owner
    rescue StandardError
      nil
    end

    def self.for_chat_message(message)
      message&.last_editor || message&.user
    rescue StandardError
      nil
    end

    def self.for_topic(topic)
      return unless topic

      actor = topic.acting_user if topic.respond_to?(:acting_user)
      return actor if actor.present?

      # The creator is a reliable actor for a new topic. For an existing topic,
      # however, falling back to Topic#user could blame the original author for
      # a direct/admin edit whose acting user was not propagated by Discourse.
      topic.user if topic.new_record?
    rescue StandardError
      nil
    end
  end
end
