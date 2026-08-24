# frozen_string_literal: true

module ::LinkSafety
  class CircuitBreaker
    def self.open?(provider)
      value = open_until(provider)
      value.present? && value > Time.zone.now
    end

    def self.open_until(provider)
      value = Discourse.redis.get(key(provider, "open_until"))
      Time.zone.at(value.to_f) if value.present?
    end

    def self.record_success(provider)
      Discourse.redis.del(key(provider, "failures"))
      Discourse.redis.del(key(provider, "open_until"))
    end

    def self.record_failure(provider)
      failures_key = key(provider, "failures")
      count = Discourse.redis.incr(failures_key)
      Discourse.redis.expire(
        failures_key,
        SiteSetting.link_safety_circuit_breaker_window_minutes.minutes.to_i,
      ) if count == 1
      if count >= SiteSetting.link_safety_circuit_breaker_failure_count
        until_time = Time.zone.now + SiteSetting.link_safety_circuit_breaker_open_minutes.minutes
        Discourse.redis.set(
          key(provider, "open_until"),
          until_time.to_f,
          ex: SiteSetting.link_safety_circuit_breaker_open_minutes.minutes.to_i,
        )
      end
      count
    end

    def self.reset!(provider)
      record_success(provider)
    end

    def self.key(provider, suffix)
      ::LinkSafety::RedisNamespace.key("circuit", provider, suffix)
    end
    private_class_method :key
  end
end
