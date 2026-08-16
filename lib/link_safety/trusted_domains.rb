# frozen_string_literal: true

module ::LinkSafety
  class TrustedDomains
    def self.trusted?(host)
      normalized = normalize(host)
      return true if normalized.blank? || local_host?(normalized)

      domains.any? do |domain|
        normalized == domain ||
          (SiteSetting.link_safety_trusted_domains_include_subdomains && normalized.end_with?(".#{domain}"))
      end
    end

    def self.domains
      SiteSetting.link_safety_trusted_domains.to_s.split("|").filter_map do |value|
        normalized = normalize(value)
        normalized if normalized.present?
      end.uniq
    end

    def self.normalize(value)
      raw = value.to_s.strip
      return if raw.blank?

      host =
        if raw.include?("://")
          Addressable::URI.parse(raw).host.to_s
        else
          raw
        end
      host = host.downcase.gsub(/\A\[|\]\z/, "")
      host = host.gsub(/\A\.+|\.+\z/, "").gsub(/\.{2,}/, ".")
      host = Addressable::IDNA.to_ascii(host).downcase unless host.ascii_only?
      host.presence
    rescue Addressable::URI::InvalidURIError, ArgumentError
      nil
    end

    def self.local_host?(host)
      local_hosts.include?(normalize(host))
    end

    def self.local_hosts
      hosts = [Discourse.current_hostname]
      [Discourse.base_url, Discourse.base_url_no_prefix, Discourse.asset_host].compact.each do |url|
        begin
          value = url.to_s.start_with?("//") ? "https:#{url}" : url.to_s
          hosts << Addressable::URI.parse(value).host
        rescue Addressable::URI::InvalidURIError
        end
      end
      hosts.compact.map { |h| normalize(h) }.compact.uniq
    end
  end
end
