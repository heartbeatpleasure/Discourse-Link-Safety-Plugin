# frozen_string_literal: true

module ::LinkSafety
  class HealthRegistry
    PREFIX = "link_safety:health".freeze

    def self.success!(provider:, latency_ms:)
      Discourse.redis.mapped_hmset(
        "#{PREFIX}:#{provider}",
        "last_success_at" => Time.zone.now.iso8601,
        "last_latency_ms" => latency_ms.to_i,
        "last_failure_at" => "",
        "last_failure_code" => "",
      )
    end

    def self.failure!(provider:, code:, latency_ms: nil)
      values = {
        "last_failure_at" => Time.zone.now.iso8601,
        "last_failure_code" => code.to_s,
      }
      values["last_latency_ms"] = latency_ms.to_i if latency_ms
      Discourse.redis.mapped_hmset("#{PREFIX}:#{provider}", values)
    end

    def self.for(provider)
      Discourse.redis.hgetall("#{PREFIX}:#{provider}") || {}
    end
  end
end
