# frozen_string_literal: true

module ::LinkSafety
  class DailyStat < ::ActiveRecord::Base
    self.table_name = "link_safety_daily_stats"
    validates :stat_date, :provider, presence: true
    validates :provider, uniqueness: { scope: :stat_date }
  end
end
