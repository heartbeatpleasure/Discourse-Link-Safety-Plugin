# frozen_string_literal: true

module ::LinkSafety
  class OneboxGate
    def self.apply!(doc)
      return doc if doc.blank? || SiteSetting.link_safety_mode != "enforce"
      doc.css("a.onebox[href], a.inline-onebox-loading[href]").each do |anchor|
        item = ::LinkSafety::Canonicalizer.call(anchor["href"])
        next unless item
        next if ::LinkSafety::TrustedDomains.local_host?(item.host) || ::LinkSafety::TrustedDomains.trusted?(item.host)
        entry = ::LinkSafety::CacheEntry.lookup(provider: SiteSetting.link_safety_provider, fingerprint: item.fingerprint, legacy_fingerprint: item.legacy_fingerprint)
        next unless entry && %w[error threat].include?(entry.verdict)

        classes = anchor["class"].to_s.split
        classes -= %w[onebox inline-onebox-loading]
        anchor["class"] = classes.join(" ")
      end
      doc
    rescue => e
      Rails.logger.warn("[LinkSafety] onebox gate failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :onebox_gate, code: e.class.name)
      # Prevent an Enforce-mode control failure from falling back to a remote
      # onebox fetch. Only onebox-loading classes on external HTTP(S) targets
      # are stripped; ordinary/internal links are left alone.
      fail_closed!(doc)
    end

    def self.fail_closed!(doc)
      doc.css("a.onebox[href], a.inline-onebox-loading[href]").each do |anchor|
        href = anchor["href"].to_s.strip
        next unless href.match?(%r{\Ahttps?://}i) || href.start_with?("//")

        classes = anchor["class"].to_s.split
        classes -= %w[onebox inline-onebox-loading]
        anchor["class"] = classes.join(" ")
      end
      doc
    rescue StandardError
      doc
    end
    private_class_method :fail_closed!
  end
end
