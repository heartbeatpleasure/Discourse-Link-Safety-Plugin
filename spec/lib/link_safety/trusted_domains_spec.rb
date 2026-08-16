# frozen_string_literal: true

RSpec.describe LinkSafety::TrustedDomains do
  before do
    SiteSetting.link_safety_trusted_domains = ""
    SiteSetting.link_safety_trusted_domains_include_subdomains = false
  end

  it "never treats a blank or invalid host as trusted" do
    expect(described_class.trusted?(nil)).to eq(false)
    expect(described_class.trusted?(" ")).to eq(false)
    expect(described_class.trusted?("http://[invalid")).to eq(false)
  end

  it "does not allow a public suffix to become a wildcard bypass" do
    SiteSetting.link_safety_trusted_domains = "com"
    SiteSetting.link_safety_trusted_domains_include_subdomains = true

    expect(described_class.trusted?("com")).to eq(true)
    expect(described_class.trusted?("example.com")).to eq(false)
  end

end
