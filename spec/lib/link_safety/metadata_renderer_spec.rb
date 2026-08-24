# frozen_string_literal: true

RSpec.describe LinkSafety::MetadataRenderer do
  before do
    SiteSetting.link_safety_enabled = true
    SiteSetting.link_safety_mode = "enforce"
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    SiteSetting.link_safety_scan_profile_links = true
    SiteSetting.link_safety_scan_group_bio_links = true
    SiteSetting.link_safety_scan_topic_featured_links = true
    SiteSetting.link_safety_profile_fail_open = false
    SiteSetting.link_safety_metadata_fail_open = false
    SiteSetting.link_safety_trusted_domains = ""
    allow(LinkSafety::TrustedDomains).to receive(:trusted?).and_return(false)
  end

  it "suppresses a profile website only while it has a current threat verdict" do
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(
      double(verdict: "threat", error_code: nil),
    )

    expect(described_class.safe_url("https://example.com/path", surface: :profile)).to be_nil
  end

  it "keeps an expired prior threat suppressed in fail-closed until it is reverified" do
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(nil)
    allow(LinkSafety::CacheEntry).to receive(:lookup_any).and_return(
      double(verdict: "threat", expires_at: 1.minute.ago),
    )

    SiteSetting.link_safety_profile_fail_open = false
    expect(described_class.safe_url("https://example.com/path", surface: :profile)).to be_nil

    SiteSetting.link_safety_profile_fail_open = true
    expect(described_class.safe_url("https://example.com/path", surface: :profile)).to eq(
      "https://example.com/path",
    )
  end

  it "keeps an unknown metadata URL visible because fail-closed is enforced at verification time" do
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(nil)

    expect(described_class.safe_url("https://example.com/path", surface: :profile)).to eq(
      "https://example.com/path",
    )
  end

  it "uses the profile-specific failure policy for cached verification errors" do
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(
      double(verdict: "error", error_code: "read_timeout"),
    )

    SiteSetting.link_safety_profile_fail_open = false
    expect(described_class.safe_url("https://example.com/path", surface: :profile)).to be_nil

    SiteSetting.link_safety_profile_fail_open = true
    expect(described_class.safe_url("https://example.com/path", surface: :profile)).to eq(
      "https://example.com/path",
    )
  end

  it "passes the metadata-specific failure policy to HTML rendering" do
    expect(LinkSafety::Renderer).to receive(:render_html).with(
      "<p>bio</p>",
      failure_policy: :fail_closed,
    ).and_return("<p>bio</p>")

    described_class.render_html("<p>bio</p>", surface: :group_profile)
  end
end
