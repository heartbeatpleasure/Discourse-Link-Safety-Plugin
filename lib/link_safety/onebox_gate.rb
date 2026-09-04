# frozen_string_literal: true

require "set"

module ::LinkSafety
  class OneboxGate
    def self.apply!(doc, target: nil)
      return doc if doc.blank? || SiteSetting.link_safety_mode != "enforce"
      verification_needed = false
      allowed_once = target ? ::LinkSafety::FinalContentGuard.peek_allowance(target) : Set.new

      doc.css("a.onebox[href], a.inline-onebox-loading[href]").each do |anchor|
        href = anchor["href"]
        next if ::LinkSafety::WarningPresenter.advisory_url?(href)

        candidate = ::LinkSafety::UrlCandidateClassifier.classify(href)
        next unless candidate.checkable?

        item = ::LinkSafety::Canonicalizer.call(candidate.url)
        unless item
          # A malformed external navigation candidate cannot be reputation-
          # checked. Never let Discourse initiate a server-side onebox fetch for
          # it in Enforce mode, irrespective of provider outage policy.
          strip_onebox_marker!(anchor)
          next
        end
        next if ::LinkSafety::TrustedDomains.trusted?(item.host)
        next if allowed_once.include?(item.fingerprint)

        entry = ::LinkSafety::CacheEntry.lookup(
          provider: SiteSetting.link_safety_provider,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )

        if entry.nil?
          verification_needed = true
          stale = ::LinkSafety::CacheEntry.lookup_any(
            provider: SiteSetting.link_safety_provider,
            fingerprint: item.fingerprint,
            legacy_fingerprint: item.legacy_fingerprint,
          )
          # A provider-backed threat is no longer current after expiry, so
          # fail-open navigation may resume according to policy. Do not,
          # however, make the server fetch/onebox a previously malicious target
          # until a fresh verification has cleared that historical state.
          if stale&.verdict == "threat" || SiteSetting.link_safety_failure_policy.to_s == "fail_closed"
            strip_onebox_marker!(anchor)
          end
        elsif %w[error threat].include?(entry.verdict)
          verification_needed ||= entry.verdict == "error" && ::LinkSafety::VerificationPolicy.retryable?(entry.error_code)
          # Never initiate a remote onebox fetch for a known threat or an
          # unverified/error result, even when normal posting is fail-open.
          strip_onebox_marker!(anchor)
        end
      end

      ::LinkSafety::FinalContentVerifier.schedule(target) if verification_needed && target
      doc
    rescue => e
      Rails.logger.warn("[LinkSafety] onebox gate failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :onebox_gate, code: e.class.name)
      fail_closed!(doc)
    end

    def self.strip_onebox_marker!(anchor)
      classes = anchor["class"].to_s.split
      classes -= %w[onebox inline-onebox-loading]
      anchor["class"] = classes.join(" ")
    end
    private_class_method :strip_onebox_marker!

    def self.fail_closed!(doc)
      doc.css("a.onebox[href], a.inline-onebox-loading[href]").each do |anchor|
        candidate = ::LinkSafety::UrlCandidateClassifier.classify(anchor["href"])
        next unless candidate.checkable?

        strip_onebox_marker!(anchor)
      end
      doc
    rescue StandardError
      doc
    end
    private_class_method :fail_closed!
  end
end
