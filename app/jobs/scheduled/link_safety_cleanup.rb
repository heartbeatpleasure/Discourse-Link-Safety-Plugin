# frozen_string_literal: true

module ::Jobs
  class LinkSafetyCleanup < ::Jobs::Scheduled
    every 1.day

    def execute(_args)
      return unless SiteSetting.link_safety_enabled
      ::LinkSafety::CacheEntry.where("expires_at < ?", 7.days.ago).delete_all
      ::LinkSafety::Detection.where("detected_at < ?", SiteSetting.link_safety_detection_retention_days.days.ago).delete_all
      ::LinkSafety::DailyStat.where("stat_date < ?", Date.current - SiteSetting.link_safety_statistics_retention_days).delete_all
    end
  end
end
