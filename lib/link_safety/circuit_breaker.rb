# frozen_string_literal: true

module ::LinkSafety
  class CircuitBreaker
    PREFIX = "link_safety:circuit".freeze

    def self.open?(provider)
      open_until(provider).present? && open_until(provider) > Time.zone.now
    end

    def self.open_until(provider)
      value = Discourse.redis.get("#{PREFIX}:#{provider}:open_until")
      Time.zone.at(value.to_f) if value.present?
    end

    def self.record_success(provider)
      Discourse.redis.del("#{PREFIX}:#{provider}:failures")
      Discourse.redis.del("#{PREFIX}:#{provider}:open_until")
    end

    def self.record_failure(provider)
      key = "#{PREFIX}:#{provider}:failures"
      count = Discourse.redis.incr(key)
      Discourse.redis.expire(key, SiteSetting.link_safety_circuit_breaker_window_minutes.minutes.to_i) if count == 1
      if count >= SiteSetting.link_safety_circuit_breaker_failure_count
        until_time = Time.zone.now + SiteSetting.link_safety_circuit_breaker_open_minutes.minutes
        Discourse.redis.set("#{PREFIX}:#{provider}:open_until", until_time.to_f, ex: SiteSetting.link_safety_circuit_breaker_open_minutes.minutes.to_i)
      end
      count
    end

    def self.reset!(provider)
      record_success(provider)
    end
  end
end
