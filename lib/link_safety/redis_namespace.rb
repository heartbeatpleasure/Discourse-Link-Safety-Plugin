# frozen_string_literal: true

module ::LinkSafety
  # Redis is shared by Discourse multisite installations. Every Link Safety key
  # must therefore carry a stable site scope so a failure/rate-limit/dedup event
  # on one site cannot influence another site that happens to use the same Redis.
  class RedisNamespace
    PREFIX = "link_safety".freeze

    def self.key(*parts)
      ([PREFIX, site_scope] + parts.flatten.compact.map(&:to_s)).join(":")
    end

    def self.site_scope
      value =
        if defined?(::RailsMultisite::ConnectionManagement)
          ::RailsMultisite::ConnectionManagement.current_db
        end
      value = ::Discourse.current_hostname if value.blank?
      value.to_s.presence || "default"
    rescue StandardError
      ::Discourse.current_hostname.to_s.presence || "default"
    end
  end
end
