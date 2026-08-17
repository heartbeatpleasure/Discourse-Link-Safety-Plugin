# frozen_string_literal: true

RSpec.describe LinkSafety::WarningPresenter do
  def result(provider)
    LinkSafety::Result.new(
      url: "https://example.com/", canonical_url: "https://example.com/", fingerprint: "a" * 64,
      host: "example.com", status: "threat", threat_types: ["MALWARE"], provider: provider,
      checked_at: Time.zone.now, expires_at: 5.minutes.from_now, error_code: nil, source: "spec",
    )
  end

  it "uses the short two-paragraph Google warning without exposing an advisory URL" do
    message = described_class.validation_message([result("safe_browsing_v5")])

    expect(message).to eq(
      "For your safety and the safety of our other members, this link can’t be posted because it may lead to a potentially unsafe website. Please remove or replace the link and try again.\n\n" \
        "Advisory provided by Google. Safe Browsing may occasionally miss unsafe sites or flag safe sites in error.",
    )
    expect(message).not_to include("http://")
    expect(message).not_to include("https://")
    expect(message).not_to include(described_class::SAFE_BROWSING_ADVISORY)
  end

  it "uses the same Google warning for Web Risk without exposing an advisory URL" do
    message = described_class.validation_message([result("web_risk_lookup")])

    expect(message).to include("\n\nAdvisory provided by Google.")
    expect(message).not_to include("http://")
    expect(message).not_to include("https://")
    expect(message).not_to include(described_class::WEB_RISK_ADVISORY)
  end

  it "does not add Google attribution to a URLhaus-only threat warning" do
    message = described_class.validation_message([result("urlhaus")])

    expect(message).to eq(
      "For your safety and the safety of our other members, this link can’t be posted because it may lead to a potentially unsafe website. Please remove or replace the link and try again.",
    )
    expect(message).not_to include("Google")
    expect(message).not_to include("http://")
    expect(message).not_to include("https://")
  end

  it "keeps Google attribution when any Google provider supplied the threat" do
    message = described_class.validation_message([result("urlhaus"), result("safe_browsing_v5")])

    expect(message).to include("Advisory provided by Google")
  end
end
