# frozen_string_literal: true

RSpec.describe LinkSafety::Fingerprint do
  it "uses a deterministic site-secret HMAC instead of a bare SHA-256 URL digest" do
    canonical = "https://example.com/private/path?token=example"
    fingerprint = described_class.for_url(canonical)

    expect(fingerprint).to match(/\A[0-9a-f]{64}\z/)
    expect(fingerprint).to eq(described_class.for_url(canonical))
    expect(fingerprint).not_to eq(Digest::SHA256.hexdigest(canonical))
  end
end
