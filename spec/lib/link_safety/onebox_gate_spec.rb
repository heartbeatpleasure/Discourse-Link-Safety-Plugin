# frozen_string_literal: true

RSpec.describe LinkSafety::OneboxGate do
  before do
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    allow(LinkSafety::SiteOrigin).to receive(:same?).and_return(false)
    allow(LinkSafety::TrustedDomains).to receive(:trusted?).and_return(false)
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(double(verdict: "error", error_code: "read_timeout"))
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
  it "never fetches a onebox for an expired historical threat while it awaits revalidation" do
    SiteSetting.link_safety_mode = "enforce"
    SiteSetting.link_safety_failure_policy = "fail_open"
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(nil)
    allow(LinkSafety::CacheEntry).to receive(:lookup_any).and_return(
      double(verdict: "threat", expires_at: 1.minute.ago),
    )
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

  it "does not suppress an internal Discourse onebox marker" do
    SiteSetting.link_safety_mode = "enforce"
    doc = Nokogiri::HTML5.fragment('<a class="onebox" href="/t/topic/1">Internal</a>')

    described_class.apply!(doc)

    expect(doc.at_css("a")["class"].to_s.split).to include("onebox")
  end


end
