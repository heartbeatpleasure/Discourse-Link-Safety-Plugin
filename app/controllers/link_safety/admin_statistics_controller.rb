# frozen_string_literal: true

module ::LinkSafety
  class AdminStatisticsController < ::Admin::AdminController
    requires_plugin ::LinkSafety::PLUGIN_NAME
    before_action { response.headers["Cache-Control"] = "no-store" }

    def index
      days = params[:days].to_i
      days = 30 unless [7, 30, 90, 365].include?(days)
      rows = ::LinkSafety::Statistics.period(days)
      render_json_dump(
        generated_at: Time.zone.now,
        days: days,
        rows: rows.map do |row|
          {
            date: row.stat_date,
            provider: row.provider,
            checks: row.checks,
            provider_calls: row.provider_calls,
            cache_hits: row.cache_hits,
            trusted_skips: row.trusted_skips,
            threats: row.threats,
            blocked: row.blocked,
            monitored: row.monitored,
            fail_open: row.fail_open,
            errors: row.error_count,
            average_latency_ms: row.latency_samples.positive? ? (row.latency_total_ms.to_f / row.latency_samples).round : nil,
          }
        end,
      )
    end
  end
end
