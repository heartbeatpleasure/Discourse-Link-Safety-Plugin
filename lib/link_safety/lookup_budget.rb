# frozen_string_literal: true

module ::LinkSafety
  # Weighted fixed-window quota for uncached external URLs that would otherwise
  # reach a remote reputation provider. It is intentionally independent from
  # Discourse's post-rate limits: edits, chat messages and high-URL submissions
  # can consume external API quota even when ordinary posting limits are obeyed.
  class LookupBudget
    USER_WINDOW_SECONDS = 10.minutes.to_i
    GLOBAL_WINDOW_SECONDS = 1.minute.to_i

    Result = Data.define(:allowed, :error_code) do
      def allowed? = allowed
    end

    def self.reserve(user:, units:)
      units = units.to_i
      return Result.new(allowed: true, error_code: nil) if units <= 0

      # Check the actor first so one abusive user cannot consume the global
      # counter simply by continuing after their own limit is exhausted.
      user_key = nil
      if user&.id
        user_key = window_key("user:#{user.id}", USER_WINDOW_SECONDS)
        allowed = reserve_window(
          key: user_key,
          units: units,
          limit: SiteSetting.link_safety_lookup_budget_per_user_10_minutes.to_i,
          ttl: USER_WINDOW_SECONDS + 5,
        )
        return Result.new(allowed: false, error_code: "user_lookup_rate_limited") unless allowed
      end

      allowed = reserve_window(
        key: window_key("global", GLOBAL_WINDOW_SECONDS),
        units: units,
        limit: SiteSetting.link_safety_lookup_budget_global_per_minute.to_i,
        ttl: GLOBAL_WINDOW_SECONDS + 5,
      )
      unless allowed
        if user_key
          remaining = Discourse.redis.decrby(user_key, units)
          Discourse.redis.del(user_key) if remaining <= 0
        end
        return Result.new(allowed: false, error_code: "global_lookup_rate_limited")
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
      count <= limit
    end
    private_class_method :reserve_window

    def self.window_key(scope, seconds)
      window = Time.now.to_i / seconds
      "link_safety:lookup_budget:#{Discourse.current_hostname}:#{scope}:#{window}"
    end
    private_class_method :window_key
  end
end
