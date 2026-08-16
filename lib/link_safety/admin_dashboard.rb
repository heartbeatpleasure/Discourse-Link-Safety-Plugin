# frozen_string_literal: true

module ::LinkSafety
  class AdminDashboard
    def self.overview
      provider = SiteSetting.link_safety_provider.to_s
      health = ::LinkSafety::HealthRegistry.for(provider)
      control_failures = ::LinkSafety::HealthRegistry.control_failures
      {
        generated_at: Time.zone.now,
        enabled: SiteSetting.link_safety_enabled,
        mode: SiteSetting.link_safety_mode,
        provider: provider,
        configured: provider_configured?(provider),
        circuit_open: ::LinkSafety::CircuitBreaker.open?(provider),
        circuit_open_until: ::LinkSafety::CircuitBreaker.open_until(provider),
        last_success_at: health["last_success_at"].presence,
        last_failure_at: health["last_failure_at"].presence,
        last_failure_code: health["last_failure_code"].presence,
        last_latency_ms: health["last_latency_ms"].presence&.to_i,
        valid_cache_entries: ::LinkSafety::CacheEntry.valid_now.where(provider: provider).count,
        detections_24h: ::LinkSafety::Detection.where("detected_at >= ?", 24.hours.ago).count,
        fail_open_24h: ::LinkSafety::DailyStat.where(stat_date: [Date.current - 1, Date.current], provider: provider).sum(:fail_open),
        provider_calls_month: ::LinkSafety::DailyStat.where(stat_date: Date.current.beginning_of_month..Date.current, provider: provider).sum(:provider_calls),
        control_failure_count: control_failures.sum { |entry| entry[:count].to_i },
        control_failures: control_failures,
      }
    end

    def self.provider_configured?(provider)
      return false if SiteSetting.link_safety_google_api_key.blank?
      return SiteSetting.link_safety_safe_browsing_noncommercial_acknowledged if provider == "safe_browsing_v5"
      true
    end
  end
end
