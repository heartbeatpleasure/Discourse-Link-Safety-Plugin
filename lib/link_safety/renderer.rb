# frozen_string_literal: true

module ::LinkSafety
  class Renderer
    BLOCKED_CLASS = "link-safety-blocked-link".freeze
    ORIGINAL_HREF_ATTRIBUTE = "data-link-safety-original-href".freeze

    def self.render_html(html, failure_policy: SiteSetting.link_safety_failure_policy)
      return html if html.blank? || SiteSetting.link_safety_mode != "enforce"
      doc = Nokogiri::HTML5.fragment(html)
      changed = render_document!(doc, failure_policy: failure_policy)
      changed ? doc.to_html : html
    rescue => e
      Rails.logger.warn("[LinkSafety] render filter failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :renderer, code: e.class.name)
      %(<p class="link-safety-warning">#{ERB::Util.html_escape(I18n.t("link_safety.rendered_content_unavailable"))}</p>)
    end

    def self.render_document!(doc, failure_policy: SiteSetting.link_safety_failure_policy)
      return false if SiteSetting.link_safety_mode != "enforce"
      changed = false
      doc.css("a[href]").each do |anchor|
        href = anchor["href"]
        next if ::LinkSafety::WarningPresenter.advisory_url?(href)

        candidate = ::LinkSafety::UrlCandidateClassifier.classify(href)
        next unless candidate.checkable?

        item = ::LinkSafety::Canonicalizer.call(candidate.url)
        unless item
          if failure_policy.to_s == "fail_closed"
            neutralize_unverified_anchor!(anchor)
            changed = true
          end
          next
        end
        next if ::LinkSafety::TrustedDomains.trusted?(item.host)

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
          if stale&.verdict == "threat" && failure_policy.to_s == "fail_closed"
            neutralize_unverified_anchor!(anchor)
            changed = true
          end
          next
        end

        if entry.verdict == "threat"
          provider = entry.source_provider.presence || entry.provider
          neutralize_anchor!(anchor, provider: provider)
          changed = true
        elsif entry.verdict == "error" &&
              ::LinkSafety::VerificationPolicy.block_errors?(
                [entry.error_code],
                failure_policy: failure_policy,
              )
          neutralize_unverified_anchor!(anchor)
          changed = true
        end
      end
      changed
    rescue => e
      Rails.logger.warn("[LinkSafety] render document failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :renderer, code: e.class.name)
      fail_closed_external_links!(doc)
    end

    def self.neutralize_anchor!(anchor, provider:)
      remember_original_href!(anchor)
      strip_navigation!(anchor)
      anchor["title"] = ::LinkSafety::WarningPresenter.validation_message_for_provider(provider)
      append_warning!(anchor, provider: provider)
      true
    end

    def self.neutralize_unverified_anchor!(anchor)
      remember_original_href!(anchor)
      strip_navigation!(anchor)
      anchor["title"] = I18n.t("link_safety.errors.unavailable")
      append_unverified_warning!(anchor)
      true
    end

    def self.original_href(anchor)
      anchor["href"].presence || anchor[ORIGINAL_HREF_ATTRIBUTE].presence
    end

    def self.fail_closed_document!(doc)
      fail_closed_external_links!(doc)
    end

    def self.remember_original_href!(anchor)
      href = anchor["href"].presence
      anchor[ORIGINAL_HREF_ATTRIBUTE] ||= href if href
    end
    private_class_method :remember_original_href!

    def self.strip_navigation!(anchor)
      anchor.remove_attribute("href")
      anchor.remove_attribute("target")
      anchor.remove_attribute("data-onebox-src")
      classes = anchor["class"].to_s.split
      classes -= %w[onebox inline-onebox inline-onebox-loading]
      classes << BLOCKED_CLASS
      anchor["class"] = classes.uniq.join(" ")
      anchor["role"] = "note"
    end
    private_class_method :strip_navigation!

    def self.fail_closed_external_links!(doc)
      changed = false
      doc.css("a[href]").each do |anchor|
        next unless external_http_href?(anchor["href"])

        neutralize_unverified_anchor!(anchor)
        changed = true
      end
      changed
    rescue StandardError
      false
    end
    private_class_method :fail_closed_external_links!

    def self.external_http_href?(href)
      ::LinkSafety::UrlCandidateClassifier.classify(href).checkable?
    rescue StandardError
      false
    end
    private_class_method :external_http_href?

    def self.append_unverified_warning!(anchor)
      return if anchor.next_element&.classes&.include?("link-safety-warning")

      warning = Nokogiri::XML::Node.new("span", anchor.document)
      warning["class"] = "link-safety-warning"
      warning.content = I18n.t("link_safety.rendered_warning_unverified")
      anchor.add_next_sibling(warning)
    end
    private_class_method :append_unverified_warning!

    def self.append_warning!(anchor, provider:)
      return if anchor.next_element&.classes&.include?("link-safety-warning")

      presentation = ::LinkSafety::WarningPresenter.rendered_warning(provider)
      warning = Nokogiri::XML::Node.new("span", anchor.document)
      warning["class"] = "link-safety-warning"

      unless presentation[:google]
        warning.content = presentation[:text]
        anchor.add_next_sibling(warning)
        return
      end

      warning.add_child(Nokogiri::XML::Text.new("#{presentation[:text]} ", anchor.document))
      advisory = Nokogiri::XML::Node.new("a", anchor.document)
      advisory["href"] = presentation[:advisory_url]
      advisory["target"] = "_blank"
      advisory["rel"] = "noopener noreferrer"
      advisory.content = presentation[:advisory_label]
      warning.add_child(advisory)
      warning.add_child(Nokogiri::XML::Text.new(". #{presentation[:accuracy_notice]}", anchor.document))
      anchor.add_next_sibling(warning)
    end
    private_class_method :append_warning!
  end
end
