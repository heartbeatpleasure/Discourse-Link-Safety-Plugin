# frozen_string_literal: true

module ::LinkSafety
  class Statistics
    ALLOWED_COUNTERS = %i[
      checks
      provider_calls
      cache_hits
      trusted_skips
      threats
      blocked
      monitored
      fail_open
      errors
      latency_total_ms
      latency_samples
    ].freeze

    CAPTURE_KEY = :link_safety_statistics_capture

    def self.bump!(provider, **counters)
      normalized = normalize_counters(counters)
      return if normalized.empty?

      if (capture = current_capture)
        merge_counters!(capture, provider, normalized)
        return
      end

      persist_counters!(provider, normalized)
    rescue => e
      Rails.logger.warn("[LinkSafety] statistics update failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :statistics, code: e.class.name)
      nil
    end

    def self.capture
      previous = current_capture
      capture = {}
      Thread.current[CAPTURE_KEY] = capture
      value = yield
      [value, deep_copy_capture(capture)]
    ensure
      Thread.current[CAPTURE_KEY] = previous
    end

    # Link checks run during Active Record validation. When validation rejects an
    # Enforce submission, any ordinary database writes performed inside that save
    # transaction are rolled back too. Register callbacks on the transaction itself
    # so real provider usage and security counters are persisted only after the
    # surrounding save has committed or rolled back.
    def self.finalize_capture!(model, capture, on_commit: nil, on_rollback: nil)
      return :empty if capture.blank?

      transaction = current_transaction_for(model)
      unless transaction
        apply_snapshot!(capture)
        return :immediate
      end

      snapshot = deep_copy_capture(capture)
      transaction.after_commit do
        begin
          apply_snapshot!(snapshot)
        ensure
          on_commit&.call
        end
      end
      transaction.after_rollback do
        begin
          apply_snapshot!(snapshot)
        ensure
          on_rollback&.call
        end
      end
      :registered
    rescue => e
      Rails.logger.warn("[LinkSafety] statistics transaction callback failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :statistics, code: e.class.name)
      apply_snapshot!(capture)
      :immediate
    end

    def self.apply_snapshot!(capture)
      capture.to_h.each do |provider, counters|
        normalized = normalize_counters(counters)
        next if normalized.empty?

        begin
          persist_counters!(provider, normalized)
        rescue => e
          Rails.logger.warn("[LinkSafety] statistics update failed class=#{e.class.name}")
          ::LinkSafety::HealthRegistry.control_failure!(component: :statistics, code: e.class.name)
        end
      end
      nil
    end

    def self.period(days)
      from = Date.current - (days - 1)
      ::LinkSafety::DailyStat.where(stat_date: from..Date.current).order(stat_date: :desc, provider: :asc)
    end

    def self.normalize_counters(counters)
      counters
        .to_h
        .symbolize_keys
        .slice(*ALLOWED_COUNTERS)
        .transform_values(&:to_i)
        .reject { |_key, value| value.zero? }
    end
    private_class_method :normalize_counters

    def self.persist_counters!(provider, counters)
      return if counters.empty?

      database_counters = counters.dup
      if database_counters.key?(:errors)
        database_counters[:error_count] = database_counters.delete(:errors)
      end

      row = begin
        ::LinkSafety::DailyStat.find_or_create_by!(stat_date: Date.current, provider: provider.to_s)
      rescue ActiveRecord::RecordNotUnique
        retry
      end
      ::LinkSafety::DailyStat.update_counters(row.id, database_counters)
    end
    private_class_method :persist_counters!

    def self.current_capture
      Thread.current[CAPTURE_KEY]
    end
    private_class_method :current_capture

    def self.merge_counters!(capture, provider, counters)
      key = provider.to_s
      capture[key] ||= {}
      counters.each do |counter, value|
        capture[key][counter] = capture[key].fetch(counter, 0).to_i + value.to_i
      end
    end
    private_class_method :merge_counters!

    def self.deep_copy_capture(capture)
      capture.to_h.each_with_object({}) do |(provider, counters), copy|
        copy[provider.to_s] = counters.to_h.transform_keys(&:to_sym).transform_values(&:to_i)
      end
    end
    private_class_method :deep_copy_capture

    def self.current_transaction_for(model)
      return unless model&.class&.respond_to?(:current_transaction)

      transaction = model.class.current_transaction
      transaction if transaction&.open?
    rescue StandardError
      nil
    end
    private_class_method :current_transaction_for
  end
end
