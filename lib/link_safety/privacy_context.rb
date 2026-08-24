# frozen_string_literal: true

module ::LinkSafety
  # Provider privacy is independent from the functional Link Safety surface.
  # A normal post can still be privacy-sensitive when it lives in a secure
  # category, is a whisper, or the whole Discourse instance requires login.
  class PrivacyContext
    def self.for_post(post)
      return true if site_private?
      return false unless post
      return true if post.respond_to?(:whisper?) && post.whisper?
      return true if post.respond_to?(:hidden?) && post.hidden?

      topic = post.topic
      return true if topic&.respond_to?(:visible) && topic.visible == false

      topic&.private_message? || topic&.category&.read_restricted? || false
    rescue StandardError
      true
    end

    def self.for_chat_message(message)
      return true if site_private?
      channel = message&.chat_channel
      return false unless channel
      return true if direct_chat_channel?(channel)

      channel.respond_to?(:read_restricted?) && channel.read_restricted?
    rescue StandardError
      true
    end

    def self.for_topic(topic)
      return true if site_private?
      return true if topic&.respond_to?(:visible) && topic.visible == false

      topic&.private_message? || topic&.category&.read_restricted? || false
    rescue StandardError
      true
    end

    def self.for_group(group)
      return true if site_private?
      return true unless group

      public_level = ::Group.visibility_levels[:public]
      group.visibility_level != public_level
    rescue StandardError
      true
    end

    def self.for_user_profile(profile)
      return true if site_private?
      return true unless profile&.user

      # Ask Discourse's anonymous Guardian rather than duplicating profile
      # visibility rules (hide-from-public, per-user hide, new-user profile
      # restrictions, etc.). If an anonymous visitor cannot see this profile,
      # a full-URL provider requires the explicit private-content opt-in.
      !::Guardian.new.can_see_profile?(profile.user)
    rescue StandardError
      true
    end

    def self.site_private?
      SiteSetting.respond_to?(:login_required) && SiteSetting.login_required
    rescue StandardError
      false
    end
    private_class_method :site_private?

    def self.direct_chat_channel?(channel)
      return false unless defined?(::Chat::Channel)

      ::Chat::Channel.direct_channel_chatable_types.include?(channel.chatable_type)
    end
    private_class_method :direct_chat_channel?
  end
end
