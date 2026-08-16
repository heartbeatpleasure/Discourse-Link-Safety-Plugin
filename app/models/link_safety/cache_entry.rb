# frozen_string_literal: true

module ::LinkSafety
  class CacheEntry < ::ActiveRecord::Base
    self.table_name = "link_safety_cache_entries"

    validates :provider, :source_provider, :url_fingerprint, :host, :verdict, :checked_at, :expires_at, presence: true
    validates :url_fingerprint, uniqueness: { scope: :provider }

    scope :valid_now, -> { where("expires_at > ?", Time.zone.now) }

    def self.lookup(provider:, fingerprint:, legacy_fingerprint: nil)
      scope = valid_now.where(provider: provider.to_s)
      entry = scope.find_by(url_fingerprint: fingerprint)
      return entry if entry || legacy_fingerprint.blank? || legacy_fingerprint.to_s == fingerprint.to_s

      scope.find_by(url_fingerprint: legacy_fingerprint)
    end
  end
end
