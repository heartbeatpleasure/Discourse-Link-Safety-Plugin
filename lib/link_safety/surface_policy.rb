# frozen_string_literal: true

module ::LinkSafety
  class SurfacePolicy
    def self.enabled?(surface)
      return false unless SiteSetting.link_safety_enabled

      case surface.to_s
      when "public_post"
        SiteSetting.link_safety_scan_public_posts
      when "private_message"
        SiteSetting.link_safety_scan_private_messages
      when "chat_public"
        SiteSetting.link_safety_scan_chat_public
      when "chat_dm"
        SiteSetting.link_safety_scan_chat_direct_messages
      when "profile"
        SiteSetting.link_safety_scan_profile_links
      when "admin_test"
        true
      else
        false
      end
    end
  end
end
