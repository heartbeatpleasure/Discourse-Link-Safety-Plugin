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
      html
    end

    def self.render_document!(doc)
      return false if SiteSetting.link_safety_mode != "enforce"
      changed = false
      doc.css("a[href]").each do |anchor|
        item = ::LinkSafety::Canonicalizer.call(anchor["href"])
        next unless item
        next if ::LinkSafety::TrustedDomains.local_host?(item.host) || ::LinkSafety::TrustedDomains.trusted?(item.host)
        entry = ::LinkSafety::CacheEntry.lookup(provider: SiteSetting.link_safety_provider, fingerprint: item.fingerprint)
        next unless entry&.verdict == "threat"

        anchor.remove_attribute("href")
        anchor.remove_attribute("target")
        anchor.remove_attribute("data-onebox-src")
        classes = anchor["class"].to_s.split
        classes -= %w[onebox inline-onebox inline-onebox-loading]
        classes << BLOCKED_CLASS
        anchor["class"] = classes.uniq.join(" ")
        anchor["role"] = "note"
        anchor["title"] = I18n.t("link_safety.errors.malicious_link")
        append_warning!(anchor, entry)
        changed = true
      end
      changed
    end
    def self.append_warning!(anchor, entry)
      return if anchor.next_element&.classes&.include?("link-safety-warning")

      warning = Nokogiri::XML::Node.new("span", anchor.document)
      warning["class"] = "link-safety-warning"
      warning.content = I18n.t("link_safety.rendered_warning")

      if google_safe_browsing_detection?(entry)
        warning.add_child(Nokogiri::XML::Text.new(" ", anchor.document))
        advisory = Nokogiri::XML::Node.new("a", anchor.document)
        advisory["href"] = "https://developers.google.com/safe-browsing/v4/advisory"
        advisory["target"] = "_blank"
        advisory["rel"] = "noopener noreferrer"
        advisory.content = I18n.t("link_safety.google_advisory")
        warning.add_child(advisory)
      end

      anchor.add_next_sibling(warning)
    end

    def self.google_safe_browsing_detection?(entry)
      SiteSetting.link_safety_provider.to_s == "safe_browsing_v5" &&
        Array(entry.threat_types).any? { |type| type.to_s != "MALWARE_DISTRIBUTION" }
    end

  end
end
