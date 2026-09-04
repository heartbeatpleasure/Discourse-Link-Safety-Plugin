# frozen_string_literal: true

require "json"
require "set"

module ::LinkSafety
  # Last line of defence for links introduced after Link Safety's normal
  # validation/cook stage (for example by another plugin). It operates on the
  # final DOM that Discourse is about to persist and never puts a full URL in a
  # background-job argument.
  class FinalContentGuard
    MODEL_ALLOWANCE_IVAR = :@link_safety_clean_fingerprints
    ALLOWANCE_TTL = 10.minutes.to_i

    def self.apply!(doc, target:)
      return doc unless SiteSetting.link_safety_enabled
      return doc if doc.blank? || target.blank?

      context = ::LinkSafety::TargetContext.for(target, extract: false)
      return doc unless context && ::LinkSafety::SurfacePolicy.enabled?(context.surface)

      # Snapshot final external candidates before Renderer potentially removes an
      # href for a cached threat/error. This lets retryable errors introduced by
      # another plugin still schedule verification after neutralisation.
      extraction = ::LinkSafety::Extractor.final_document_result(doc)
      raise "final content extraction failed" if extraction.error_code.present?
      allowed_once = consume_allowance(target)
      verification_needed = false

      extraction.urls.each do |url|
        next if ::LinkSafety::WarningPresenter.advisory_url?(url)

        item = ::LinkSafety::Canonicalizer.call(url)
        next unless item
        next if ::LinkSafety::TrustedDomains.trusted?(item.host)
        next if allowed_once.include?(item.fingerprint)

        entry = ::LinkSafety::CacheEntry.lookup(
          provider: SiteSetting.link_safety_provider,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        verification_needed ||= entry.nil? ||
          (entry.verdict == "error" && ::LinkSafety::VerificationPolicy.retryable?(entry.error_code))
      end

      ::LinkSafety::Renderer.render_document!(doc)

      # Unknown plugin-introduced links are only temporarily neutralised when
      # the site's existing fail-closed policy requires it. Known cached errors
      # and threats have already been handled by Renderer above.
      doc.css("a[href]").each do |anchor|
        href = anchor["href"]
        next if ::LinkSafety::WarningPresenter.advisory_url?(href)

        candidate = ::LinkSafety::UrlCandidateClassifier.classify(href)
        next unless candidate.checkable?
        item = ::LinkSafety::Canonicalizer.call(candidate.url)
        unless item
          if SiteSetting.link_safety_mode.to_s == "enforce" &&
               SiteSetting.link_safety_failure_policy.to_s == "fail_closed"
            ::LinkSafety::Renderer.neutralize_unverified_anchor!(anchor)
          end
          next
        end
        next if ::LinkSafety::TrustedDomains.trusted?(item.host)
        next if allowed_once.include?(item.fingerprint)

        entry = ::LinkSafety::CacheEntry.lookup(
          provider: SiteSetting.link_safety_provider,
          fingerprint: item.fingerprint,
          legacy_fingerprint: item.legacy_fingerprint,
        )
        if entry.nil? && SiteSetting.link_safety_mode.to_s == "enforce" &&
             SiteSetting.link_safety_failure_policy.to_s == "fail_closed"
          ::LinkSafety::Renderer.neutralize_unverified_anchor!(anchor)
        end
      end

      ::LinkSafety::FinalContentVerifier.schedule(target) if verification_needed
      doc
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] final content guard failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :final_content_guard, code: e.class.name)
      if doc
        if SiteSetting.link_safety_mode.to_s == "enforce" &&
             SiteSetting.link_safety_failure_policy.to_s == "fail_closed"
          ::LinkSafety::Renderer.fail_closed_document!(doc)
        else
          ::LinkSafety::Renderer.render_document!(doc)
        end
      end
      doc
    end

    # Capture synchronous clean responses on the Active Record instance. The
    # after_commit callback can then bind them to the persisted target/content.
    # This is especially important for Web Risk, whose clean Lookup response has
    # no reusable negative-cache lifetime.
    def self.remember_clean_results!(model, results)
      fingerprints = Array(results).select(&:clean?).map(&:fingerprint).compact.uniq
      return if fingerprints.empty?

      model.instance_variable_set(MODEL_ALLOWANCE_IVAR, fingerprints)
    rescue StandardError
      nil
    end

    def self.persist_model_allowance!(target)
      fingerprints = target.instance_variable_get(MODEL_ALLOWANCE_IVAR)
      return if fingerprints.blank? || target.id.blank?

      store_allowance(target, fingerprints)
      target.remove_instance_variable(MODEL_ALLOWANCE_IVAR) if target.instance_variable_defined?(MODEL_ALLOWANCE_IVAR)
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] final allowance persist failed class=#{e.class.name}")
      nil
    end

    def self.allow_once!(target, fingerprints)
      store_allowance(target, Array(fingerprints).compact.uniq)
    end

    def self.peek_allowance(target)
      raw = Discourse.redis.get(allowance_key(target))
      Array(raw.present? ? JSON.parse(raw) : []).map(&:to_s).to_set
    rescue StandardError
      Set.new
    end

    def self.consume_allowance(target)
      key = allowance_key(target)
      values = peek_allowance(target)
      Discourse.redis.del(key) if values.any?
      values
    rescue StandardError
      Set.new
    end

    def self.store_allowance(target, fingerprints)
      return if fingerprints.blank?
      Discourse.redis.setex(allowance_key(target), ALLOWANCE_TTL, fingerprints.to_json)
    end
    private_class_method :store_allowance

    def self.allowance_key(target)
      ::LinkSafety::RedisNamespace.key(
        "final_allow_once",
        target.class.name,
        target.id,
        ::LinkSafety::RetryContext.content_hash_for(target),
        ::LinkSafety::RetryContext.content_version_for(target),
      )
    end
    private_class_method :allowance_key
  end
end
