# frozen_string_literal: true

module ::LinkSafety
  class CacheEntry < ::ActiveRecord::Base
    self.table_name = "link_safety_cache_entries"

    validates :provider, :url_fingerprint, :host, :verdict, :checked_at, :expires_at, presence: true
    validates :url_fingerprint, uniqueness: { scope: :provider }

    scope :valid_now, -> { where("expires_at > ?", Time.zone.now) }

    def self.lookup(provider:, fingerprint:)
      valid_now.find_by(provider: provider.to_s, url_fingerprint: fingerprint)
    end
  end
end
