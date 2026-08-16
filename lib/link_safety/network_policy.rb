# frozen_string_literal: true

require "ipaddr"

module ::LinkSafety
  class NetworkPolicy
    PRIVATE_SURFACES = %i[private_message chat_dm].freeze
    NON_PUBLIC_NETWORKS = %w[
      0.0.0.0/8
      10.0.0.0/8
      100.64.0.0/10
      127.0.0.0/8
      169.254.0.0/16
      172.16.0.0/12
      192.0.0.0/24
      192.0.2.0/24
      192.168.0.0/16
      198.18.0.0/15
      198.51.100.0/24
      203.0.113.0/24
      224.0.0.0/4
      240.0.0.0/4
      ::/128
      ::1/128
      fc00::/7
      fe80::/10
      2001:db8::/32
      ff00::/8
    ].map { |cidr| IPAddr.new(cidr) }.freeze

    def self.private_surface?(surface)
      PRIVATE_SURFACES.include?(surface.to_s.to_sym)
    end

    def self.private_or_special_host?(host)
      value = host.to_s.downcase.gsub(/\A\[|\]\z/, "").sub(/\.$/, "")
      return true if value.blank?
      return true if value == "localhost" || !value.include?(".")
      return true if value.end_with?(".localhost", ".local", ".internal", ".home", ".lan")

      ip = IPAddr.new(value)
      NON_PUBLIC_NETWORKS.any? { |network| network.include?(ip) }
    rescue IPAddr::InvalidAddressError
      false
    end

    # Web Risk Lookup sends the complete URL to Google. Privacy-sensitive
    # surfaces and non-public network locations require explicit opt-in.
    def self.web_risk_allowed?(item, surface:)
      if private_surface?(surface) && !SiteSetting.link_safety_web_risk_private_surfaces
        return [false, "private_surface_lookup_disabled"]
      end
      if private_or_special_host?(item.host) && !SiteSetting.link_safety_full_url_providers_allow_private_networks
        return [false, "private_network_full_url_provider_disabled"]
      end
      [true, nil]
    end

    def self.urlhaus_allowed?(item, surface:)
      if private_surface?(surface) && !SiteSetting.link_safety_urlhaus_private_surfaces
        return false
      end
      return false if private_or_special_host?(item.host) && !SiteSetting.link_safety_full_url_providers_allow_private_networks

      true
    end
  end
end
