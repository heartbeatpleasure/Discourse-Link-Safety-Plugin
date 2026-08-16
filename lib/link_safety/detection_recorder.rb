# frozen_string_literal: true

module ::LinkSafety
  class DetectionRecorder
    BLOCKED_QUEUE_IVAR = :@_link_safety_blocked_detection_queue

    def self.record!(result:, surface:, user:, action:, target: nil, count_statistics: true)
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
      if count_statistics
        ::LinkSafety::Statistics.bump!(result.provider, threats: 1, **action_counter(action))
      end
      if user.present? && action.to_s != "monitor_only"
        ::LinkSafety::UserNoteWriter.maybe_add!(user: user, detection: detection)
      end
      detection
    rescue => e
      Rails.logger.warn("[LinkSafety] detection record failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :detection_recorder, code: e.class.name)
      nil
    end

    def self.queue_blocked!(model:, result:, surface:, user:)
      queue = model.instance_variable_get(BLOCKED_QUEUE_IVAR) || []
      key = [result.provider.to_s, result.fingerprint.to_s, surface.to_s, user&.id]
      unless queue.any? { |entry| entry[:key] == key }
        queue << { key: key, result: result, surface: surface.to_s, user: user }
        model.instance_variable_set(BLOCKED_QUEUE_IVAR, queue)
        ::LinkSafety::Statistics.bump!(result.provider, threats: 1, blocked: 1)
      end
      nil
    end

    def self.take_queued!(model)
      queue = model.instance_variable_get(BLOCKED_QUEUE_IVAR)
      clear_queued!(model)
      Array(queue)
    end

    def self.flush_entries!(entries, target: nil)
      Array(entries).each do |entry|
        record!(
          result: entry[:result],
          surface: entry[:surface],
          user: entry[:user],
          action: :blocked_before_save,
          target: target,
          count_statistics: false,
        )
      end
      nil
    end

    def self.clear_queued!(model)
      model.remove_instance_variable(BLOCKED_QUEUE_IVAR) if model.instance_variable_defined?(BLOCKED_QUEUE_IVAR)
    rescue NameError
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
