# frozen_string_literal: true

module ::Jobs
  class LinkSafetyCleanup < ::Jobs::Scheduled
    every 1.day

    def execute(_args)
      # Expired positive verdicts are retained as historical evidence until a
      # fresh provider response explicitly clears them. Their provider-backed
      # expiry is never extended, and only fail-closed presentation/onebox
      # policy consults this historical state. Removing them on a timer could
      # silently reopen a previously malicious link during a long provider
      # outage. Clean/error cache state can be discarded normally.
      ::LinkSafety::CacheEntry
        .where.not(verdict: "threat")
        .where("expires_at < ?", 7.days.ago)
        .delete_all
      ::LinkSafety::Detection.where("detected_at < ?", SiteSetting.link_safety_detection_retention_days.days.ago).delete_all
      ::LinkSafety::DailyStat.where("stat_date < ?", Date.current - SiteSetting.link_safety_statistics_retention_days).delete_all
    end
  end
end
