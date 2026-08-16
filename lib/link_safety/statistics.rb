# frozen_string_literal: true

module ::LinkSafety
  class Statistics
    ALLOWED_COUNTERS = %i[checks provider_calls cache_hits trusted_skips threats blocked monitored fail_open errors latency_total_ms latency_samples].freeze

    def self.bump!(provider, **counters)
      counters = counters.slice(*ALLOWED_COUNTERS).transform_values(&:to_i).reject { |_k, v| v.zero? }
      return if counters.empty?

      row = begin
        ::LinkSafety::DailyStat.find_or_create_by!(stat_date: Date.current, provider: provider.to_s)
      rescue ActiveRecord::RecordNotUnique
        retry
      end
      ::LinkSafety::DailyStat.update_counters(row.id, counters)
    rescue => e
      Rails.logger.warn("[LinkSafety] statistics update failed class=#{e.class.name}")
    end

    def self.period(days)
      from = Date.current - (days - 1)
      ::LinkSafety::DailyStat.where(stat_date: from..Date.current).order(:stat_date, :provider)
    end
  end
end
