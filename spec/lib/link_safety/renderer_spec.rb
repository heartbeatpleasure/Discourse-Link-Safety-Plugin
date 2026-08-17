# frozen_string_literal: true

RSpec.describe LinkSafety::Renderer do
  before do
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    SiteSetting.link_safety_trusted_domains = ""
    allow(LinkSafety::TrustedDomains).to receive(:local_host?).and_return(false)
    allow(LinkSafety::TrustedDomains).to receive(:trusted?).and_return(false)
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(
      double(
        verdict: "threat", threat_types: ["MALWARE"], source_provider: "safe_browsing_v5",
        provider: "safe_browsing_v5", checked_at: Time.zone.now, expires_at: 5.minutes.from_now,
      ),
    )
  end

  it "leaves threat links untouched in monitor mode" do
    SiteSetting.link_safety_mode = "monitor"
    html = '<p><a href="https://example.com/path">Example</a></p>'
    expect(described_class.render_html(html)).to eq(html)
  end

  it "neutralizes a cached threat link in enforce mode" do
    SiteSetting.link_safety_mode = "enforce"
    html = '<p><a href="https://example.com/path" target="_blank">Example</a></p>'
    output = described_class.render_html(html)
    doc = Nokogiri::HTML5.fragment(output)
    anchor = doc.at_css("a")
    expect(anchor["href"]).to be_nil
    expect(anchor["target"]).to be_nil
    expect(anchor["class"].to_s.split).to include("link-safety-blocked-link")
    warning = doc.at_css(".link-safety-warning")
    expect(warning).to be_present
    advisory = warning.at_css("a")
    expect(advisory).to be_present
    expect(advisory.text).to eq("Advisory provided by Google")
    expect(advisory["href"]).to eq(LinkSafety::WarningPresenter::SAFE_BROWSING_ADVISORY)
    expect(warning.text).not_to include(LinkSafety::WarningPresenter::SAFE_BROWSING_ADVISORY)
    expect(warning.text).not_to include("https://")
  end
  it "does not add Google attribution to a URLhaus-only cached threat" do
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(
      double(
        verdict: "threat", threat_types: ["MALWARE"], source_provider: "urlhaus",
        provider: "safe_browsing_v5", checked_at: Time.zone.now, expires_at: 5.minutes.from_now,
      ),
    )
    SiteSetting.link_safety_mode = "enforce"

    output = described_class.render_html('<p><a href="https://example.com/path">Example</a></p>')
    warning = Nokogiri::HTML5.fragment(output).at_css(".link-safety-warning")

    expect(warning.text).to eq(I18n.t("link_safety.rendered_warning"))
    expect(warning.at_css("a")).to be_nil
  end

  it "fails closed for external links if Enforce rendering raises internally" do
    SiteSetting.link_safety_mode = "enforce"
    allow(LinkSafety::Canonicalizer).to receive(:call).and_raise(StandardError, "boom")
    allow(LinkSafety::HealthRegistry).to receive(:control_failure!)

    output = described_class.render_html('<p><a href="https://example.com/path">Example</a><a href="/internal">Internal</a></p>')
    doc = Nokogiri::HTML5.fragment(output)

    expect(doc.css("a")[0]["href"]).to be_nil
    expect(doc.css("a")[1]["href"]).to eq("/internal")
    expect(doc.at_css(".link-safety-warning").text).to eq(I18n.t("link_safety.rendered_warning_unverified"))
  end

end
