# frozen_string_literal: true

RSpec.describe LinkSafety::CacheEntry do
  before { described_class.delete_all }

  it "preserves old SHA-256 cache verdicts during the HMAC fingerprint transition" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    legacy = described_class.create!(
      provider: "safe_browsing_v5",
      source_provider: "safe_browsing_v5",
      url_fingerprint: item.legacy_fingerprint,
      host: item.host,
      verdict: "threat",
      threat_types: ["MALWARE"],
      checked_at: Time.zone.now,
      expires_at: 10.minutes.from_now,
    )

    found = described_class.lookup(
      provider: "safe_browsing_v5",
      fingerprint: item.fingerprint,
      legacy_fingerprint: item.legacy_fingerprint,
    )

    expect(found.id).to eq(legacy.id)
  end

  it "stores the provider that actually supplied the cached verdict" do
    row = described_class.create!(
      provider: "safe_browsing_v5",
      source_provider: "urlhaus",
      url_fingerprint: "a" * 64,
      host: "example.com",
      verdict: "threat",
      threat_types: ["MALWARE_DISTRIBUTION"],
      checked_at: Time.zone.now,
      expires_at: 10.minutes.from_now,
    )

    expect(row.source_provider).to eq("urlhaus")
  end
end
