# frozen_string_literal: true

RSpec.describe LinkSafety::WarningPresenter do
  def result(provider)
    LinkSafety::Result.new(
      url: "https://example.com/", canonical_url: "https://example.com/", fingerprint: "a" * 64,
      host: "example.com", status: "threat", threat_types: ["MALWARE"], provider: provider,
      checked_at: Time.zone.now, expires_at: 5.minutes.from_now, error_code: nil, source: "spec",
    )
  end

  it "adds Google attribution only to Google-backed threat warnings" do
    expect(described_class.validation_message([result("safe_browsing_v5")])).to include("Advisory provided by Google")
    expect(described_class.validation_message([result("web_risk_lookup")])).to include("Advisory provided by Google")
    expect(described_class.validation_message([result("urlhaus")])).not_to include("Google")
  end
end
