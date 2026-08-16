# frozen_string_literal: true

RSpec.describe LinkSafety::NetworkPolicy do
  Item = Data.define(:host)

  before do
    SiteSetting.link_safety_web_risk_private_surfaces = false
    SiteSetting.link_safety_urlhaus_private_surfaces = false
    SiteSetting.link_safety_full_url_providers_allow_private_networks = false
  end

  describe ".private_or_special_host?" do
    %w[
      localhost
      localhost.localdomain
      internal
      server.lan
      127.0.0.1
      10.1.2.3
      172.16.1.1
      192.168.1.1
      169.254.169.254
      ::1
      [fe80::1]
      [fc00::1]
      service.test
      hidden.onion
      reserved.invalid
      host.alt
    ].each do |host|
      it "treats #{host} as non-public" do
        expect(described_class.private_or_special_host?(host)).to eq(true)
      end
    end

    it "allows an ordinary public hostname" do
      expect(described_class.private_or_special_host?("example.com")).to eq(false)
    end
  end

  describe ".web_risk_allowed?" do
    it "does not send full private-message URLs without explicit opt-in" do
      allowed, code = described_class.web_risk_allowed?(Item.new(host: "example.com"), surface: :private_message)
      expect(allowed).to eq(false)
      expect(code).to eq("private_surface_lookup_disabled")
    end

    it "does not send private-network URLs to a full-URL provider by default" do
      SiteSetting.link_safety_web_risk_private_surfaces = true
      allowed, code = described_class.web_risk_allowed?(Item.new(host: "10.0.0.10"), surface: :private_message)
      expect(allowed).to eq(false)
      expect(code).to eq("private_network_full_url_provider_disabled")
    end

    it "allows both privacy-sensitive categories only after explicit opt-in" do
      SiteSetting.link_safety_web_risk_private_surfaces = true
      SiteSetting.link_safety_full_url_providers_allow_private_networks = true
      allowed, code = described_class.web_risk_allowed?(Item.new(host: "10.0.0.10"), surface: :private_message)
      expect(allowed).to eq(true)
      expect(code).to be_nil
    end
  end

  it "treats common internal and reverse-DNS namespaces as non-public" do
    expect(described_class.private_or_special_host?("metadata.google.internal")).to eq(true)
    expect(described_class.private_or_special_host?("host.localdomain")).to eq(true)
    expect(described_class.private_or_special_host?("1.0.0.127.in-addr.arpa")).to eq(true)
  end

end
