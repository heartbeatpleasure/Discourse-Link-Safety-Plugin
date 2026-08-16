# frozen_string_literal: true

module ::LinkSafety
  class DetectionRecorder
    def self.record!(result:, surface:, user:, action:, target: nil)
      detection = ::LinkSafety::Detection.create!(
        detected_at: Time.zone.now,
        provider: result.provider,
        url_fingerprint: result.fingerprint,
        host: result.host,
        threat_types: result.threat_types,
        user_id: user&.id,
        surface: surface.to_s,
        action: action.to_s,
        target_type: target&.class&.name,
        target_id: target&.id,
      )
      ::LinkSafety::Statistics.bump!(result.provider, threats: 1, **action_counter(action))
      if user.present? && action.to_s != "monitor_only"
        ::LinkSafety::UserNoteWriter.maybe_add!(user: user, detection: detection)
      end
      detection
    rescue => e
      Rails.logger.warn("[LinkSafety] detection record failed class=#{e.class.name}")
      nil
    end

    def self.action_counter(action)
      case action.to_s
      when "blocked_before_save", "disabled_after_publish"
        { blocked: 1 }
      when "monitor_only"
        { monitored: 1 }
      else
        {}
      end
    end
  end
end
