# frozen_string_literal: true

RSpec.describe LinkSafety::OneboxGate do
  before do
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    allow(LinkSafety::TrustedDomains).to receive(:local_host?).and_return(false)
    allow(LinkSafety::TrustedDomains).to receive(:trusted?).and_return(false)
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(double(verdict: "error"))
  end

  it "does not suppress oneboxes in monitor mode" do
    SiteSetting.link_safety_mode = "monitor"
    doc = Nokogiri::HTML5.fragment('<a class="onebox" href="https://example.com/">Example</a>')
    described_class.apply!(doc)
    expect(doc.at_css("a")["class"].split).to include("onebox")
  end

  it "suppresses a pending onebox fetch in enforce mode" do
    SiteSetting.link_safety_mode = "enforce"
    doc = Nokogiri::HTML5.fragment('<a class="onebox" href="https://example.com/">Example</a>')
    described_class.apply!(doc)
    expect(doc.at_css("a")["class"].to_s.split).not_to include("onebox")
  end
  it "removes external onebox loading classes if the gate fails internally in Enforce mode" do
    SiteSetting.link_safety_mode = "enforce"
    allow(LinkSafety::Canonicalizer).to receive(:call).and_raise(StandardError, "boom")
    allow(LinkSafety::HealthRegistry).to receive(:control_failure!)
    doc = Nokogiri::HTML5.fragment(
      '<a class="onebox" href="https://example.com/">External</a><a class="onebox" href="/internal">Internal</a>',
    )

    described_class.apply!(doc)

    expect(doc.css("a")[0]["class"].to_s.split).not_to include("onebox")
    expect(doc.css("a")[1]["class"].to_s.split).to include("onebox")
  end

end
