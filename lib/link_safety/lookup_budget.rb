# frozen_string_literal: true

module ::LinkSafety
  # Weighted fixed-window quota for uncached external URLs that would otherwise
  # reach a remote reputation provider. A configurable part of the global
  # budget is reserved for security retries/revalidation (and staff), so a noisy
  # ordinary user cannot starve remediation after content has already published.
  class LookupBudget
    USER_WINDOW_SECONDS = 10.minutes.to_i
    GLOBAL_WINDOW_SECONDS = 1.minute.to_i

    Result = Data.define(:allowed, :error_code) do
      def allowed? = allowed
    end

    def self.reserve(user:, units:, priority: :normal)
      units = units.to_i
      return Result.new(allowed: true, error_code: nil) if units <= 0

      security_priority = priority.to_s == "security" || !!user&.staff?

      # Check the actor first so one abusive user cannot consume the global
      # counter simply by continuing after their own limit is exhausted. Security
      # retries intentionally bypass the user window because they are follow-up
      # work for already accepted content, not fresh user traffic.
      user_key = nil
      if user&.id && !security_priority
        user_key = window_key("user:#{user.id}", USER_WINDOW_SECONDS)
        allowed = reserve_window(
          key: user_key,
          units: units,
          limit: SiteSetting.link_safety_lookup_budget_per_user_10_minutes.to_i,
          ttl: USER_WINDOW_SECONDS + 5,
        )
        return Result.new(allowed: false, error_code: "user_lookup_rate_limited") unless allowed
      end

      global_limit = SiteSetting.link_safety_lookup_budget_global_per_minute.to_i
      reserve_percent = SiteSetting.link_safety_lookup_budget_security_reserve_percent.to_i.clamp(0, 50)
      ordinary_limit = [global_limit - ((global_limit * reserve_percent) / 100), 1].max
      effective_limit = security_priority ? global_limit : ordinary_limit

      allowed = reserve_window(
        key: window_key("global", GLOBAL_WINDOW_SECONDS),
        units: units,
        limit: effective_limit,
        ttl: GLOBAL_WINDOW_SECONDS + 5,
      )
      unless allowed
        Discourse.redis.decrby(user_key, units) if user_key
        return Result.new(
          allowed: false,
          error_code: security_priority ? "security_lookup_rate_limited" : "global_lookup_rate_limited",
        )
      end

      Result.new(allowed: true, error_code: nil)
    rescue => e
      Rails.logger.warn("[LinkSafety] lookup budget failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :lookup_budget, code: e.class.name)
      Result.new(allowed: false, error_code: "lookup_budget_unavailable")
    end

    def self.reserve_window(key:, units:, limit:, ttl:)
      count = Discourse.redis.incrby(key, units)
      # The first reservation defines the fixed window. A later reservation does
      # not extend it, preventing a permanently sliding lockout under load.
      Discourse.redis.expire(key, ttl) if count == units
      return true if count <= limit

      # A rejected reservation must not itself burn the reserved security
      # capacity. Roll back this caller's units while preserving concurrent
      # successful reservations in the same fixed window.
      Discourse.redis.decrby(key, units)
      false
    end
    private_class_method :reserve_window

    def self.window_key(scope, seconds)
      window = Time.now.to_i / seconds
      ::LinkSafety::RedisNamespace.key("lookup_budget", scope, window)
    end
    private_class_method :window_key
  end
end
