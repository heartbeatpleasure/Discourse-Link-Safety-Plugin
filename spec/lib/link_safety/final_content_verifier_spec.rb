# frozen_string_literal: true

RSpec.describe LinkSafety::FinalContentVerifier do
  let(:target) { double("target", id: 123, cooked: '<a href="https://example.com/">x</a>') }
  let(:extraction) do
    LinkSafety::Extractor::Extraction.new(urls: ["https://example.com/"], error_code: nil)
  end
  let(:context) do
    LinkSafety::TargetContext::Context.new(
      surface: :public_post,
      actor: nil,
      private_content: false,
      extraction: extraction,
    )
  end
  let(:threat) do
    LinkSafety::Result.new(
      url: "https://example.com/",
      canonical_url: "https://example.com/",
      fingerprint: "a" * 64,
      host: "example.com",
      status: "threat",
      threat_types: ["MALWARE"],
      provider: "safe_browsing_v5",
      checked_at: Time.zone.now,
      expires_at: 5.minutes.from_now,
      error_code: nil,
      source: "spec",
    )
  end

  before do
    SiteSetting.link_safety_enabled = true
    SiteSetting.link_safety_mode = "enforce"
    allow(LinkSafety::RetryContext).to receive(:content_hash_for).with(target).and_return("start-hash")
    allow(LinkSafety::RetryContext).to receive(:content_version_for).with(target).and_return("start-version")
    allow(LinkSafety::TargetContext).to receive(:for).with(target).and_return(context)
    allow(LinkSafety::SurfacePolicy).to receive(:enabled?).with(:public_post).and_return(true)
    allow(LinkSafety::Extractor).to receive(:final_document_result).and_return(
      LinkSafety::Extractor::Extraction.new(urls: [], error_code: nil),
    )
    allow(described_class).to receive(:due_urls).and_return([["https://example.com/"], {}])
    allow(LinkSafety::Checker).to receive(:check_many).and_return([threat])
    allow(LinkSafety::RetryContext).to receive(:reload_matches_content?).and_return(false)
    allow(LinkSafety::DetectionRecorder).to receive(:record!)
    allow(LinkSafety::FinalContentGuard).to receive(:allow_once!)
    allow(described_class).to receive(:rebake)
  end

  it "does not apply a provider response when the target changes during verification" do
    result = described_class.verify!(target, revalidation: true)

    expect(LinkSafety::Checker).to have_received(:check_many)
    expect(LinkSafety::RetryContext).to have_received(:reload_matches_content?).with(
      target,
      "start-hash",
      expected_version: "start-version",
    )
    expect(result.checked).to eq(1)
    expect(result.threats).to eq([])
    expect(result.errors).to eq([])
    expect(LinkSafety::DetectionRecorder).not_to have_received(:record!)
    expect(LinkSafety::FinalContentGuard).not_to have_received(:allow_once!)
    expect(described_class).not_to have_received(:rebake)
  end

  it "rebakes a PostLocalization through Discourse's localized cooked job" do
    SiteSetting.link_safety_enabled = false
    localization = Fabricate(:post_localization)
    SiteSetting.link_safety_enabled = true

    expect(Jobs).to receive(:enqueue).with(
      :process_localized_cooked,
      post_localization_id: localization.id,
      recook: true,
    )

    described_class.send(:rebake, localization)
  end
end
