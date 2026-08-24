# frozen_string_literal: true

require "digest"

module ::LinkSafety
  class Checker
    def self.check_many(
      urls,
      surface:,
      force: false,
      bypass_circuit: false,
      bypass_lookup_budget: false,
      bypass_trusted: false,
      user: nil,
      private_content: false,
      priority: :normal
    )
      new(
        surface: surface,
        force: force,
        bypass_circuit: bypass_circuit,
        bypass_lookup_budget: bypass_lookup_budget,
        bypass_trusted: bypass_trusted,
        user: user,
        private_content: private_content,
        priority: priority,
      ).check_many(urls)
    end

    def initialize(
      surface:,
      force: false,
      bypass_circuit: false,
      bypass_lookup_budget: false,
      bypass_trusted: false,
      user: nil,
      private_content: false,
      priority: :normal
    )
      @surface = surface.to_sym
      @force = force
      @bypass_circuit = bypass_circuit
      @bypass_lookup_budget = bypass_lookup_budget
      @bypass_trusted = bypass_trusted
      @provider_name = SiteSetting.link_safety_provider.to_s
      @user = user
      @private_content = !!private_content
      @priority = priority.to_s.to_sym
    end

    def check_many(urls)
      # Keep every direct Checker caller behind the same browser-aware candidate
      # classifier. This prevents a future caller from accidentally feeding a
      # same-origin/generated Discourse href straight into canonicalization.
      candidates = ::LinkSafety::UrlCandidateClassifier.filter(urls)
      outcomes = candidates.map { |url| [url, ::LinkSafety::Canonicalizer.analyze(url)] }
      results = outcomes.filter_map do |url, outcome|
        unverified_result(url, outcome.error_code) if outcome.error?
      end
      canonical = outcomes.filter_map { |_url, outcome| outcome.item if outcome.ok? }.uniq(&:fingerprint)

      check_count = canonical.length + results.length
      ::LinkSafety::Statistics.bump!(@provider_name, checks: check_count) if check_count.positive?
      ::LinkSafety::Statistics.bump!(@provider_name, errors: results.length) if results.any?
      return results if canonical.empty?

      unresolved = []
      canonical.each do |item|
        if !@bypass_trusted && ::LinkSafety::TrustedDomains.trusted?(item.host)
          ::LinkSafety::Statistics.bump!(@provider_name, trusted_skips: 1)
          results << build_result(
            item,
            status: "trusted",
            threats: [],
            expires_at: 100.years.from_now,
            source: "trusted",
          )
          next
        end

        unless @force
          cached = ::LinkSafety::CacheEntry.lookup(
            provider: @provider_name,
            fingerprint: item.fingerprint,
            legacy_fingerprint: item.legacy_fingerprint,
          )
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
        unresolved.each { |item| results << persist_response(item, error_response("circuit_open")) }
        return results
      end

      unless reserve_lookup_budget(unresolved.length, results, unresolved)
        return results
      end

      primary_provider = provider
      deadline = primary_provider.validation_deadline
      provider_results = primary_provider.check_many(unresolved, deadline: deadline)
      unresolved.each do |item|
        response = provider_results[item.fingerprint] || error_response("missing_provider_result")
        result =
          if SiteSetting.link_safety_urlhaus_enabled
            apply_urlhaus(item, response, deadline: deadline)
          else
            persist_response(item, response)
          end
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
        allowed, error_code = ::LinkSafety::NetworkPolicy.web_risk_allowed?(
          item,
          surface: @surface,
          private_content: @private_content,
        )
        unless allowed
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

    def reserve_lookup_budget(units, results, items)
      return true if @bypass_lookup_budget

      lookup_budget = ::LinkSafety::LookupBudget.reserve(
        user: @user,
        units: units,
        priority: @priority,
      )
      return true if lookup_budget.allowed?

      ::LinkSafety::Statistics.bump!(@provider_name, errors: items.length)
      items.each do |item|
        results << build_result(
          item,
          status: "error",
          threats: [],
          expires_at: Time.zone.now + 1.minute,
          error_code: lookup_budget.error_code,
          source: "lookup_budget",
        )
      end
      false
    end

    def apply_urlhaus(item, primary_response, deadline:)
      # A primary threat/error is already decisive. Persist it once and avoid an
      # unnecessary full-URL supplemental request.
      unless primary_response.status.to_s == "clean"
        return persist_response(item, primary_response)
      end

      allowed, _error_code = ::LinkSafety::NetworkPolicy.urlhaus_allowed?(
        item,
        surface: @surface,
        private_content: @private_content,
      )
      # Supplemental URLhaus must never make an otherwise privacy-preserving
      # primary provider unusable merely because full-URL sharing is disabled.
      # If URLhaus already supplied a still-valid positive verdict before that
      # privacy policy changed, retain it until its provider-backed expiry; a
      # clean primary verdict is not evidence that URLhaus itself cleared it.
      unless allowed
        current = ::LinkSafety::CacheEntry.lookup(
          provider: @provider_name,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        source = current&.source_provider.presence || current&.provider
        return result_from_cache(item, current) if current&.verdict == "threat" && source == "urlhaus"

        return persist_response(item, primary_response)
      end

      unless @bypass_lookup_budget
        budget = ::LinkSafety::LookupBudget.reserve(user: @user, units: 1, priority: @priority)
        unless budget.allowed?
          return persist_response(
            item,
            error_response(budget.error_code),
            source_override: "lookup_budget",
          )
        end
      end

      response = ::LinkSafety::Providers::Urlhaus.new.check(
        item,
        deadline: deadline,
        bypass_circuit: @bypass_circuit,
      )

      if response.status == "threat"
        # A positive URLhaus verdict has its own validity window. Never cap it
        # by a Web Risk clean response whose documented negative TTL is zero.
        persist_response(item, response, source_override: "urlhaus", result_provider: "urlhaus")
      elsif response.status == "error"
        persist_response(item, response, source_override: "urlhaus", result_provider: "urlhaus")
      else
        # Clean supplemental results can only shorten, never extend, the primary
        # provider's clean lifetime. Persist only the combined final verdict so
        # a transient URLhaus failure can never erase a still-valid prior threat
        # during the gap between primary and supplemental calls.
        expiries = [primary_response.expires_at, response.expires_at].compact
        combined = Providers::Base::Response.new(
          status: "clean",
          threat_types: [],
          expires_at: expiries.min,
          error_code: nil,
          latency_ms: response.latency_ms,
          provider_calls: response.provider_calls,
        )
        persist_response(item, combined)
      end
    end

    def persist_response(item, response, source_override: nil, result_provider: nil)
      source_name = source_override || @provider_name
      expiry = response.expires_at || 1.minute.from_now
      now = Time.zone.now

      # A refresh failure must not erase a prior positive verdict row. Its
      # provider-backed expiry is never extended; renderers may use the expired
      # row only as historical evidence to stay generically fail-closed while a
      # fresh verdict is unavailable.
      if response.status.to_s == "error"
        current = ::LinkSafety::CacheEntry.lookup_any(
          provider: @provider_name,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        if current&.verdict == "threat"
          return build_result(
            item,
            status: response.status,
            threats: response.threat_types,
            expires_at: response.expires_at,
            error_code: response.error_code,
            source: source_name,
            provider: result_provider || @provider_name,
          )
        end
      end

      # Web Risk Lookup has no documented reusable negative-cache lifetime.
      # An already-expired result is valid for this request but must not become
      # reusable cache state.
      if expiry > now
        ::LinkSafety::CacheEntry.upsert(
          {
            provider: @provider_name,
            source_provider: result_provider || @provider_name,
            url_fingerprint: item.fingerprint,
            host: item.host,
            verdict: response.status,
            threat_types: response.threat_types,
            error_code: response.error_code,
            checked_at: now,
            expires_at: expiry,
            created_at: now,
            updated_at: now,
          },
          unique_by: :idx_link_safety_cache_provider_url,
        )
      elsif response.status.to_s == "clean"
        # Web Risk Lookup deliberately has no reusable negative-cache lifetime.
        # A fresh clean verdict must nevertheless clear an older threat/error
        # row for this exact URL; otherwise periodic revalidation could prove a
        # link clean while serializers/renderers keep seeing the stale row.
        fingerprints = [item.fingerprint, item.legacy_fingerprint].compact.uniq
        ::LinkSafety::CacheEntry.where(
          provider: @provider_name,
          url_fingerprint: fingerprints,
        ).delete_all
      end
      build_result(
        item,
        status: response.status,
        threats: response.threat_types,
        expires_at: response.expires_at,
        error_code: response.error_code,
        source: source_name,
        provider: result_provider || @provider_name,
      )
    rescue => e
      Rails.logger.warn("[LinkSafety] cache write failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :cache_write, code: e.class.name)
      build_result(
        item,
        status: response.status,
        threats: response.threat_types,
        expires_at: response.expires_at,
        error_code: response.error_code,
        source: source_name,
        provider: result_provider || @provider_name,
      )
    end

    def result_from_cache(item, cached)
      source_provider = cached.source_provider.presence || cached.provider
      build_result(
        item,
        status: cached.verdict,
        threats: Array(cached.threat_types),
        expires_at: cached.expires_at,
        error_code: cached.error_code,
        source: "cache",
        provider: source_provider,
      )
    end

    def build_result(item, status:, threats:, expires_at:, error_code: nil, source:, provider: @provider_name)
      ::LinkSafety::Result.new(
        url: item.original,
        canonical_url: item.full_url,
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
        fingerprint: ::LinkSafety::Fingerprint.for_unverified(url),
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
