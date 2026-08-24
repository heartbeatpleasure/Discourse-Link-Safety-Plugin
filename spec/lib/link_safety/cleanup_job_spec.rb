# frozen_string_literal: true

RSpec.describe Jobs::LinkSafetyCleanup do
  it "keeps expired threat history while pruning expired non-threat cache state" do
    old = 8.days.ago
    base = {
      provider: "safe_browsing_v5",
      source_provider: "safe_browsing_v5",
      host: "example.com",
      threat_types: [],
      error_code: nil,
      checked_at: old,
      expires_at: old,
    }
    threat = LinkSafety::CacheEntry.create!(
      **base,
      url_fingerprint: "a" * 64,
      verdict: "threat",
      threat_types: ["MALWARE"],
    )
    clean = LinkSafety::CacheEntry.create!(
      **base,
      url_fingerprint: "b" * 64,
      verdict: "clean",
    )
    error = LinkSafety::CacheEntry.create!(
      **base,
      url_fingerprint: "c" * 64,
      verdict: "error",
      error_code: "read_timeout",
    )

    described_class.new.execute({})

    expect(LinkSafety::CacheEntry.exists?(threat.id)).to eq(true)
    expect(LinkSafety::CacheEntry.exists?(clean.id)).to eq(false)
    expect(LinkSafety::CacheEntry.exists?(error.id)).to eq(false)
  end
end
