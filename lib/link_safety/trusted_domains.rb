# frozen_string_literal: true

require "mini_suffix"

module ::LinkSafety
  class TrustedDomains
    def self.trusted?(host)
      normalized = normalize(host)
      return false if normalized.blank?
      domains.any? do |domain|
        normalized == domain ||
          (
            SiteSetting.link_safety_trusted_domains_include_subdomains &&
              subdomain_trust_root?(domain) &&
              normalized.end_with?(".#{domain}")
          )
      end
    end


    def self.subdomain_trust_root?(domain)
      value = domain.to_s
      return false if value.blank?

      # A setting such as `com` or `co.uk` must never turn into a wildcard
      # reputation-check bypass for an entire public suffix. MiniSuffix returns
      # a registrable domain only when the value contains an actual registrable
      # label. Exact matching remains available for unusual/internal hosts.
      MiniSuffix.domain(value).present?
    rescue StandardError
      false
    end
    private_class_method :subdomain_trust_root?

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

  end
end
