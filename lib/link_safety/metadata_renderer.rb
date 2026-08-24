# frozen_string_literal: true

module ::LinkSafety
  # Non-destructive presentation guard for persisted metadata surfaces. The
  # original value stays in the model/database; serializers only suppress or
  # neutralize it while a current Link Safety verdict requires that. This means
  # periodic revalidation can restore content after an explicit clean verdict.
  class MetadataRenderer
    def self.safe_url(url, surface:)
      return url if url.blank? || !SiteSetting.link_safety_enabled
      return url unless SiteSetting.link_safety_mode.to_s == "enforce"
      return url unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      candidate = ::LinkSafety::UrlCandidateClassifier.classify(url)
      return url unless candidate.checkable?

      item = ::LinkSafety::Canonicalizer.call(candidate.url)
      return nil unless item
      return url if ::LinkSafety::TrustedDomains.trusted?(item.host)

      entry = ::LinkSafety::CacheEntry.lookup(
        provider: SiteSetting.link_safety_provider,
        fingerprint: item.fingerprint,
        legacy_fingerprint: item.legacy_fingerprint,
      )
      unless entry
        stale = ::LinkSafety::CacheEntry.lookup_any(
          provider: SiteSetting.link_safety_provider,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        if stale&.verdict == "threat" && failure_policy_for(surface).to_s == "fail_closed"
          return nil
        end
        return url
      end
      return nil if entry.verdict == "threat"

      if entry.verdict == "error" &&
           ::LinkSafety::VerificationPolicy.block_errors?(
             [entry.error_code],
             failure_policy: failure_policy_for(surface),
           )
        return nil
      end

      url
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] metadata URL rendering failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :metadata_renderer, code: e.class.name)
      failure_policy_for(surface).to_s == "fail_closed" ? nil : url
    end

    def self.render_html(html, surface:)
      return html if html.blank? || !SiteSetting.link_safety_enabled
      return html unless SiteSetting.link_safety_mode.to_s == "enforce"
      return html unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      ::LinkSafety::Renderer.render_html(html, failure_policy: failure_policy_for(surface))
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] metadata HTML rendering failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :metadata_renderer, code: e.class.name)
      failure_policy_for(surface).to_s == "fail_closed" ? nil : html
    end

    def self.failure_policy_for(surface)
      case surface.to_s
      when "profile"
        SiteSetting.link_safety_profile_fail_open ? :fail_open : :fail_closed
      when "topic_featured_link", "group_profile"
        SiteSetting.link_safety_metadata_fail_open ? :fail_open : :fail_closed
      else
        SiteSetting.link_safety_failure_policy.to_s.to_sym
      end
    end
  end
end
