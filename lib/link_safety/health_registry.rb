# frozen_string_literal: true

module ::LinkSafety
  class HealthRegistry
    PREFIX = "link_safety:health".freeze
    CONTROL_TTL_SECONDS = 1.hour.to_i
    CONTROL_COMPONENTS = %w[
      canonicalizer
      extractor
      cache_write
      detection_recorder
      statistics
      renderer
      onebox_gate
      pending_scheduler
      provider_request
      lookup_budget
    ].freeze

    def self.success!(provider:, latency_ms:)
      Discourse.redis.mapped_hmset(
        "#{PREFIX}:#{provider}",
        "last_success_at" => Time.zone.now.iso8601,
        "last_latency_ms" => latency_ms.to_i,
        "last_failure_at" => "",
        "last_failure_code" => "",
      )
    end

    def self.failure!(provider:, code:, latency_ms: nil)
      values = {
        "last_failure_at" => Time.zone.now.iso8601,
        "last_failure_code" => code.to_s,
      }
      values["last_latency_ms"] = latency_ms.to_i if latency_ms
      Discourse.redis.mapped_hmset("#{PREFIX}:#{provider}", values)
    end

    def self.for(provider)
      Discourse.redis.hgetall("#{PREFIX}:#{provider}") || {}
    end

    def self.control_failure!(component:, code:)
      component = component.to_s
      component = "unknown" unless CONTROL_COMPONENTS.include?(component)
      state_key = control_state_key(component)
      count_key = control_count_key(component)

      count = Discourse.redis.incr(count_key)
      Discourse.redis.expire(count_key, CONTROL_TTL_SECONDS)
      Discourse.redis.mapped_hmset(
        state_key,
        "last_failure_at" => Time.zone.now.iso8601,
        "last_failure_code" => code.to_s,
      )
      Discourse.redis.expire(state_key, CONTROL_TTL_SECONDS)
      nil
    rescue => e
      Rails.logger.warn("[LinkSafety] control-health update failed class=#{e.class.name}")
      nil
    end

    def self.control_failures
      (CONTROL_COMPONENTS + ["unknown"]).filter_map do |component|
        state = Discourse.redis.hgetall(control_state_key(component)) || {}
        count = Discourse.redis.get(control_count_key(component)).to_i
        next if count.zero? && state.empty?

        {
          component: component,
          count: count,
          last_failure_at: state["last_failure_at"].presence,
          last_failure_code: state["last_failure_code"].presence,
        }
      end
    rescue => e
      Rails.logger.warn("[LinkSafety] control-health read failed class=#{e.class.name}")
      []
    end

    def self.control_state_key(component)
      "#{PREFIX}:control:#{component}:state"
    end
    private_class_method :control_state_key

    def self.control_count_key(component)
      "#{PREFIX}:control:#{component}:count"
    end
    private_class_method :control_count_key
  end
end
