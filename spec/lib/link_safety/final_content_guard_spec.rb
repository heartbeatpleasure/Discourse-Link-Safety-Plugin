# frozen_string_literal: true

RSpec.describe LinkSafety::FinalContentGuard do
  let(:target) { double("target", id: 123, class: Post) }
  let(:context) do
    LinkSafety::TargetContext::Context.new(
      surface: :public_post, actor: nil, private_content: false, extraction: nil,
    )
  end

  before do
    SiteSetting.link_safety_enabled = true
    SiteSetting.link_safety_mode = "enforce"
    SiteSetting.link_safety_failure_policy = "fail_closed"
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    SiteSetting.link_safety_trusted_domains = ""
    allow(LinkSafety::TargetContext).to receive(:for).and_return(context)
    allow(LinkSafety::SurfacePolicy).to receive(:enabled?).and_return(true)
    allow(described_class).to receive(:consume_allowance).and_return(Set.new)
    allow(LinkSafety::FinalContentVerifier).to receive(:schedule)
    allow(LinkSafety::CacheEntry).to receive(:lookup).and_return(nil)
  end

  it "temporarily neutralizes and schedules a final plugin-introduced unknown link in fail-closed mode" do
    doc = Nokogiri::HTML5.fragment('<p><a href="https://external.example/path">External</a></p>')
    described_class.apply!(doc, target: target)

    anchor = doc.at_css("a")
    expect(anchor["href"]).to be_nil
    expect(anchor[LinkSafety::Renderer::ORIGINAL_HREF_ATTRIBUTE]).to eq("https://external.example/path")
    expect(LinkSafety::FinalContentVerifier).to have_received(:schedule).with(target)
  end

  it "leaves an unknown final link clickable in fail-open while still scheduling verification" do
    SiteSetting.link_safety_failure_policy = "fail_open"
    doc = Nokogiri::HTML5.fragment('<p><a href="https://external.example/path">External</a></p>')
    described_class.apply!(doc, target: target)

    expect(doc.at_css("a")["href"]).to eq("https://external.example/path")
    expect(LinkSafety::FinalContentVerifier).to have_received(:schedule).with(target)
  end
end
