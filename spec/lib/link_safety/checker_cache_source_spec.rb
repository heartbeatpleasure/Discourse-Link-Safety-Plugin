# frozen_string_literal: true

RSpec.describe "LinkSafety::Checker cached source attribution" do
  before do
    LinkSafety::CacheEntry.delete_all
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    SiteSetting.link_safety_trusted_domains = ""
    allow(LinkSafety::Statistics).to receive(:bump!)
  end

  it "returns the provider that actually supplied a cached supplemental verdict" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    LinkSafety::CacheEntry.create!(
      provider: "safe_browsing_v5",
      source_provider: "urlhaus",
      url_fingerprint: item.fingerprint,
      host: item.host,
      verdict: "threat",
      threat_types: ["MALWARE_DISTRIBUTION"],
      checked_at: Time.zone.now,
      expires_at: 10.minutes.from_now,
    )

    result = LinkSafety::Checker.check_many(["https://example.com/"], surface: :public_post).first

    expect(result.provider).to eq("urlhaus")
    expect(result.source).to eq("cache")
    expect(result.threat?).to eq(true)
  end
end
