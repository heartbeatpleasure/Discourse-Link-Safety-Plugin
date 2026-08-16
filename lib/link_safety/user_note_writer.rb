# frozen_string_literal: true

module ::LinkSafety
  class UserNoteWriter
    def self.maybe_add!(user:, detection:)
      mode = SiteSetting.link_safety_user_notes_mode.to_s
      return if mode == "off"
      return unless defined?(::DiscourseUserNotes)
      return unless SiteSetting.respond_to?(:user_notes_enabled) && SiteSetting.user_notes_enabled

      threshold_count = SiteSetting.link_safety_repeat_threat_threshold_count.to_i
      threshold_hours = SiteSetting.link_safety_repeat_threat_threshold_hours.to_i
      count = ::LinkSafety::Detection.where(user_id: user.id).where.not(action: "monitor_only").where("detected_at >= ?", threshold_hours.hours.ago).count
      return if mode == "threshold_only" && count < threshold_count

      marker = "link-safety-threshold:#{detection.id}"
      redis_key = "link_safety:user_note:#{user.id}"
      return if Discourse.redis.get(redis_key).present? && mode == "threshold_only"

      raw = I18n.t("link_safety.user_note", count: count, hours: threshold_hours, threat: Array(detection.threat_types).first || "unknown")
      ::DiscourseUserNotes.add_note(user, raw, Discourse::SYSTEM_USER_ID, plugin: "link_safety", marker: marker)
      Discourse.redis.set(redis_key, "1", ex: threshold_hours.hours.to_i) if mode == "threshold_only"
    rescue => e
      Rails.logger.warn("[LinkSafety] user note integration failed class=#{e.class.name}")
    end
  end
end
