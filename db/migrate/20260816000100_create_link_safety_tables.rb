# frozen_string_literal: true

class CreateLinkSafetyTables < ActiveRecord::Migration[7.0]
  def change
    create_table :link_safety_cache_entries do |t|
      t.string :provider, null: false, limit: 32
      t.string :url_fingerprint, null: false, limit: 64
      t.string :host, null: false, limit: 255
      t.string :verdict, null: false, limit: 16
      t.jsonb :threat_types, null: false, default: []
      t.string :error_code, limit: 64
      t.datetime :checked_at, null: false
      t.datetime :expires_at, null: false
      t.timestamps null: false
    end
    add_index :link_safety_cache_entries,
              %i[provider url_fingerprint],
              unique: true,
              name: "idx_link_safety_cache_provider_url"
    add_index :link_safety_cache_entries, :expires_at, name: "idx_link_safety_cache_expiry"

    create_table :link_safety_detections do |t|
      t.datetime :detected_at, null: false
      t.string :provider, null: false, limit: 32
      t.string :url_fingerprint, null: false, limit: 64
      t.string :host, null: false, limit: 255
      t.jsonb :threat_types, null: false, default: []
      t.integer :user_id
      t.string :surface, null: false, limit: 32
      t.string :action, null: false, limit: 32
      t.string :target_type, limit: 32
      t.bigint :target_id
      t.timestamps null: false
    end
    add_index :link_safety_detections, :detected_at, name: "idx_link_safety_detection_time"
    add_index :link_safety_detections, %i[user_id detected_at], name: "idx_link_safety_detection_user_time"
    add_index :link_safety_detections, %i[host detected_at], name: "idx_link_safety_detection_host_time"
    add_foreign_key :link_safety_detections, :users, column: :user_id, on_delete: :nullify

    create_table :link_safety_daily_stats do |t|
      t.date :stat_date, null: false
      t.string :provider, null: false, limit: 32
      t.integer :checks, null: false, default: 0
      t.integer :provider_calls, null: false, default: 0
      t.integer :cache_hits, null: false, default: 0
      t.integer :trusted_skips, null: false, default: 0
      t.integer :threats, null: false, default: 0
      t.integer :blocked, null: false, default: 0
      t.integer :monitored, null: false, default: 0
      t.integer :fail_open, null: false, default: 0
      t.integer :errors, null: false, default: 0
      t.bigint :latency_total_ms, null: false, default: 0
      t.integer :latency_samples, null: false, default: 0
      t.timestamps null: false
    end
    add_index :link_safety_daily_stats,
              %i[stat_date provider],
              unique: true,
              name: "idx_link_safety_stats_date_provider"
  end
end
