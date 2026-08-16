# frozen_string_literal: true

class FixLinkSafetyDailyStatsErrorColumn < ActiveRecord::Migration[7.0]
  def up
    return unless column_exists?(:link_safety_daily_stats, :errors)
    return if column_exists?(:link_safety_daily_stats, :error_count)

    rename_column :link_safety_daily_stats, :errors, :error_count
  end

  def down
    return unless column_exists?(:link_safety_daily_stats, :error_count)
    return if column_exists?(:link_safety_daily_stats, :errors)

    rename_column :link_safety_daily_stats, :error_count, :errors
  end
end
