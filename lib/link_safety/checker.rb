# frozen_string_literal: true

require "digest"

module ::LinkSafety
  class Checker
    def self.check_many(urls, surface:, force: false, bypass_circuit: false)
      new(surface: surface, force: force, bypass_circuit: bypass_circuit).check_many(urls)
    end

    def initialize(surface:, force: false, bypass_circuit: false)
      @surface = surface.to_sym
      @force = force
      @bypass_circuit = bypass_circuit
      @provider_name = SiteSetting.link_safety_provider.to_s
    end

    def check_many(urls)
      outcomes = Array(urls).compact.uniq.map { |url| [url, ::LinkSafety::Canonicalizer.analyze(url)] }
      results = outcomes.filter_map do |url, outcome|
        unverified_result(url, outcome.error_code) if outcome.error?
      end
      canonical = outcomes.filter_map { |_url, outcome| outcome.item if outcome.ok? }
      canonical.reject! { |item| ::LinkSafety::TrustedDomains.local_host?(item.host) }
      canonical = canonical.uniq(&:fingerprint)

      check_count = canonical.length + results.length
      ::LinkSafety::Statistics.bump!(@provider_name, checks: check_count) if check_count.positive?
      ::LinkSafety::Statistics.bump!(@provider_name, errors: results.length) if results.any?
      return results if canonical.empty?

      unresolved = []
      canonical.each do |item|
        if ::LinkSafety::TrustedDomains.trusted?(item.host)
          ::LinkSafety::Statistics.bump!(@provider_name, trusted_skips: 1)
          results << build_result(item, status: "trusted", threats: [], expires_at: 100.years.from_now, source: "trusted")
          next
        end

        unless @force
          cached = ::LinkSafety::CacheEntry.lookup(provider: @provider_name, fingerprint: item.fingerprint)
          if cached
            ::LinkSafety::Statistics.bump!(@provider_name, cache_hits: 1)
            results << result_from_cache(item, cached)
            next
          end
        end
        unresolved << item
      end

      return results if unresolved.empty?

      unresolved = apply_primary_privacy_policy(unresolved, results)
      return results if unresolved.empty?

      if !@bypass_circuit && ::LinkSafety::CircuitBreaker.open?(@provider_name)
        unresolved.each do |item|
          results << persist_response(item, error_response("circuit_open"))
        end
        return results
      end

      provider_results = provider.check_many(unresolved)
      unresolved.each do |item|
        response = provider_results[item.fingerprint] || error_response("missing_provider_result")
        result = persist_response(item, response)
        result = apply_urlhaus(item, result)
        results << result
      end
      results
    end

    private

    def provider
      case @provider_name
      when "web_risk_lookup"
        ::LinkSafety::Providers::GoogleWebRisk.new
      else
        ::LinkSafety::Providers::GoogleSafeBrowsingV5.new
      end
    end

    def apply_primary_privacy_policy(items, results)
      return items unless @provider_name == "web_risk_lookup"

      items.select do |item|
        allowed, error_code = ::LinkSafety::NetworkPolicy.web_risk_allowed?(item, surface: @surface)
        if !allowed
          ::LinkSafety::Statistics.bump!(@provider_name, errors: 1)
          results << build_result(
            item,
            status: "error",
            threats: [],
            expires_at: Time.zone.now + 1.minute,
            error_code: error_code,
            source: "privacy_policy",
          )
        end
        allowed
      end
    end

    def apply_urlhaus(item, result)
      return result unless SiteSetting.link_safety_urlhaus_enabled
      return result if result.threat? || result.error?
      return result unless ::LinkSafety::NetworkPolicy.urlhaus_allowed?(item, surface: @surface)

      threat = ::LinkSafety::Providers::Urlhaus.new.check(item)
      return result if threat.blank?
      response = Providers::Base::Response.new(status: "threat", threat_types: (result.threat_types + [threat]).uniq, expires_at: [result.expires_at, 12.hours.from_now].compact.min, error_code: nil, latency_ms: nil, provider_calls: 0)
      persist_response(item, response, source_override: "urlhaus", result_provider: "urlhaus")
    end

    def persist_response(item, response, source_override: nil, result_provider: nil)
      source_name = source_override || @provider_name
      ::LinkSafety::CacheEntry.upsert(
        {
          provider: @provider_name,
          url_fingerprint: item.fingerprint,
          host: item.host,
          verdict: response.status,
          threat_types: response.threat_types,
          error_code: response.error_code,
          checked_at: Time.zone.now,
          expires_at: response.expires_at || 1.minute.from_now,
          created_at: Time.zone.now,
          updated_at: Time.zone.now,
        },
        unique_by: :idx_link_safety_cache_provider_url,
      )
      build_result(item, status: response.status, threats: response.threat_types, expires_at: response.expires_at, error_code: response.error_code, source: source_name, provider: result_provider || @provider_name)
    rescue => e
      Rails.logger.warn("[LinkSafety] cache write failed class=#{e.class.name}")
      build_result(item, status: response.status, threats: response.threat_types, expires_at: response.expires_at, error_code: response.error_code, source: source_name, provider: result_provider || @provider_name)
    end

    def result_from_cache(item, cached)
      build_result(item, status: cached.verdict, threats: Array(cached.threat_types), expires_at: cached.expires_at, error_code: cached.error_code, source: "cache")
    end

    def build_result(item, status:, threats:, expires_at:, error_code: nil, source:, provider: @provider_name)
      ::LinkSafety::Result.new(
        url: item.original,
        canonical_url: item.canonical,
        fingerprint: item.fingerprint,
        host: item.host,
        status: status,
        threat_types: Array(threats),
        provider: provider,
        checked_at: Time.zone.now,
        expires_at: expires_at,
        error_code: error_code,
        source: source,
      )
    end

    def unverified_result(url, error_code)
      ::LinkSafety::Result.new(
        url: url.to_s,
        canonical_url: nil,
        fingerprint: Digest::SHA256.hexdigest("unverified:#{url}"),
        host: best_effort_host(url),
        status: "error",
        threat_types: [],
        provider: @provider_name,
        checked_at: Time.zone.now,
        expires_at: Time.zone.now + 1.minute,
        error_code: error_code.to_s,
        source: "canonicalizer",
      )
    end

    def best_effort_host(url)
      value = url.to_s
      value = "http://#{value}" unless value.match?(%r{\A[a-z][a-z0-9+.-]*://}i)
      Addressable::URI.parse(value).host.to_s.downcase.presence || "unavailable"
    rescue StandardError
      "unavailable"
    end

    def error_response(code)
      Providers::Base::Response.new(
        status: "error",
        threat_types: [],
        expires_at: Time.zone.now + 1.minute,
        error_code: code.to_s,
        latency_ms: nil,
        provider_calls: 0,
      )
    end
  end
end
