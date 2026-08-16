# frozen_string_literal: true

module ::LinkSafety
  class Renderer
    BLOCKED_CLASS = "link-safety-blocked-link".freeze

    def self.render_html(html)
      return html if html.blank? || SiteSetting.link_safety_mode != "enforce"
      doc = Nokogiri::HTML5.fragment(html)
      changed = render_document!(doc)
      changed ? doc.to_html : html
    rescue => e
      Rails.logger.warn("[LinkSafety] render filter failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :renderer, code: e.class.name)
      # If even the cooked fragment cannot be parsed, do not return the original
      # HTML in Enforce mode. Hiding the affected cooked content is safer than
      # accidentally restoring an external link after a security-control fault.
      %(<p class="link-safety-warning">#{ERB::Util.html_escape(I18n.t("link_safety.rendered_content_unavailable"))}</p>)
    end

    def self.render_document!(doc)
      return false if SiteSetting.link_safety_mode != "enforce"
      changed = false
      doc.css("a[href]").each do |anchor|
        item = ::LinkSafety::Canonicalizer.call(anchor["href"])
        next unless item
        next if ::LinkSafety::TrustedDomains.local_host?(item.host) || ::LinkSafety::TrustedDomains.trusted?(item.host)
        entry = ::LinkSafety::CacheEntry.lookup(provider: SiteSetting.link_safety_provider, fingerprint: item.fingerprint, legacy_fingerprint: item.legacy_fingerprint)
        next unless entry&.verdict == "threat"

        provider = entry.source_provider.presence || entry.provider
        neutralize_anchor!(anchor, provider: provider)
        changed = true
      end
      changed
    rescue => e
      Rails.logger.warn("[LinkSafety] render document failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :renderer, code: e.class.name)
      # In Enforce mode an internal rendering failure must not leave an
      # external link clickable. Fall back to neutralising external HTTP(S)
      # anchors without attributing them to Google because no verdict source
      # can be established safely in this error path.
      fail_closed_external_links!(doc)
    end

    def self.neutralize_anchor!(anchor, provider:)
      anchor.remove_attribute("href")
      anchor.remove_attribute("target")
      anchor.remove_attribute("data-onebox-src")
      classes = anchor["class"].to_s.split
      classes -= %w[onebox inline-onebox inline-onebox-loading]
      classes << BLOCKED_CLASS
      anchor["class"] = classes.uniq.join(" ")
      anchor["role"] = "note"
      anchor["title"] = ::LinkSafety::WarningPresenter.validation_message_for_provider(provider)
      append_warning!(anchor, provider: provider)
    end
    private_class_method :neutralize_anchor!

    def self.fail_closed_external_links!(doc)
      changed = false
      doc.css("a[href]").each do |anchor|
        next unless external_http_href?(anchor["href"])

        anchor.remove_attribute("href")
        anchor.remove_attribute("target")
        anchor.remove_attribute("data-onebox-src")
        classes = anchor["class"].to_s.split
        classes -= %w[onebox inline-onebox inline-onebox-loading]
        classes << BLOCKED_CLASS
        anchor["class"] = classes.uniq.join(" ")
        anchor["role"] = "note"
        anchor["title"] = I18n.t("link_safety.errors.unavailable")
        append_unverified_warning!(anchor)
        changed = true
      end
      changed
    rescue StandardError
      false
    end
    private_class_method :fail_closed_external_links!

    def self.external_http_href?(href)
      value = href.to_s.strip
      value.match?(%r{\Ahttps?://}i) || value.start_with?("//")
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

  end
end
