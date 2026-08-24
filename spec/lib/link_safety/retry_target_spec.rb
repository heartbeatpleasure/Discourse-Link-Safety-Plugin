# frozen_string_literal: true

RSpec.describe Jobs::LinkSafetyRetryTarget do
  subject(:job) { described_class.new }

  let(:target) { Object.new }
  let(:user) { Fabricate(:user) }
  let(:extraction) { LinkSafety::Extractor::Extraction.new(urls: ["https://example.com/"], error_code: nil) }
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

  let(:provider_error) do
    LinkSafety::Result.new(
      url: "https://example.com/",
      canonical_url: "https://example.com/",
      fingerprint: "b" * 64,
      host: "example.com",
      status: "error",
      threat_types: [],
      provider: "safe_browsing_v5",
      checked_at: Time.zone.now,
      expires_at: 1.minute.from_now,
      error_code: "read_timeout",
      source: "spec",
    )
  end

  before do
    SiteSetting.link_safety_enabled = true
    allow(LinkSafety::SurfacePolicy).to receive(:enabled?).and_return(true)
    allow(job).to receive(:find_target).and_return(target)
    allow(LinkSafety::RetryContext).to receive(:matches_content?).and_return(true)
    allow(job).to receive(:target_extraction).and_return([extraction, user])
    allow(job).to receive(:current_verdicts).and_return({})
    allow(job).to receive(:rebake)
    allow(job).to receive(:schedule_threat_refresh)
    allow(LinkSafety::Checker).to receive(:check_many).and_return([threat])
    allow(LinkSafety::DetectionRecorder).to receive(:record!)
  end

  it "records a post-publish retry threat as monitor-only when the current mode is Monitor" do
    SiteSetting.link_safety_mode = "monitor"

    job.execute(target_type: "Post", target_id: 1, surface: "public_post", attempt: 1)

    expect(LinkSafety::DetectionRecorder).to have_received(:record!).with(
      hash_including(action: :monitor_only, target: target),
    )
    expect(LinkSafety::Checker).to have_received(:check_many).with(
      extraction.urls,
      surface: :public_post,
      force: true,
      bypass_circuit: false,
      user: user,
    )
  end

  it "records a post-publish retry threat as disabled when the current mode is Enforce" do
    SiteSetting.link_safety_mode = "enforce"

    job.execute(target_type: "Post", target_id: 1, surface: "public_post", attempt: 1)

    expect(LinkSafety::DetectionRecorder).to have_received(:record!).with(
      hash_including(action: :disabled_after_publish, target: target),
    )
  end

  it "preserves actor and content identity when a provider error is retried again" do
    allow(LinkSafety::Checker).to receive(:check_many).and_return([provider_error])
    expect(Jobs).to receive(:enqueue_in).with(
      2.minutes,
      :link_safety_retry_target,
      hash_including(
        target_type: "Post",
        target_id: 1,
        surface: "public_post",
        attempt: 2,
        actor_id: user.id,
        content_hash: "same-hash",
      ),
    )

    job.execute(
      target_type: "Post",
      target_id: 1,
      surface: "public_post",
      attempt: 1,
      actor_id: user.id,
      content_hash: "same-hash",
    )
  end

  it "does no retry work when the target content changed after scheduling" do
    allow(LinkSafety::RetryContext).to receive(:matches_content?).with(target, "old-hash").and_return(false)

    job.execute(
      target_type: "Post",
      target_id: 1,
      surface: "public_post",
      attempt: 1,
      actor_id: user.id,
      content_hash: "old-hash",
    )

    expect(LinkSafety::Checker).not_to have_received(:check_many)
  end

  it "does no retry work after the surface has been disabled" do
    allow(LinkSafety::SurfacePolicy).to receive(:enabled?).with(:public_post).and_return(false)

    job.execute(target_type: "Post", target_id: 1, surface: "public_post", attempt: 1)

    expect(LinkSafety::Checker).not_to have_received(:check_many)
  end
end
