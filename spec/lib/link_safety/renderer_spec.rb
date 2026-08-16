# frozen_string_literal: true

RSpec.describe LinkSafety::Renderer do
  before do
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    SiteSetting.link_safety_trusted_domains = ""
    allow(LinkSafety::TrustedDomains).to receive(:local_host?).and_return(false)
    allow(LinkSafety::TrustedDomains).to receive(:trusted?).and_return(false)
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(double(verdict: "threat", threat_types: ["MALWARE"]))
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
    expect(warning.at_css("a")).to be_nil
  end
end
