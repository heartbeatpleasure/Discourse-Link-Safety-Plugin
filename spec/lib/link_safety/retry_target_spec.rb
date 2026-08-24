# frozen_string_literal: true

RSpec.describe Jobs::LinkSafetyRetryTarget do
  subject(:job) { described_class.new }

  let(:target) { Object.new }
  let(:user) { Fabricate(:user) }
  let(:extraction) { LinkSafety::Extractor::Extraction.new(urls: ["https://example.com/"], error_code: nil) }
  let(:context) do
    LinkSafety::TargetContext::Context.new(
      surface: :public_post,
      actor: user,
      private_content: true,
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
    allow(LinkSafety::RetryContext).to receive(:content_hash_for).and_return("guard-hash")
    allow(LinkSafety::RetryContext).to receive(:content_version_for).and_return("guard-version")
    allow(LinkSafety::RetryContext).to receive(:reload_matches_content?).and_return(true)
    allow(LinkSafety::TargetContext).to receive(:for).and_return(context)
    allow(job).to receive(:current_verdicts).and_return({})
    allow(job).to receive(:rebake)
    allow(job).to receive(:schedule_threat_refresh)
    allow(LinkSafety::Checker).to receive(:check_many).and_return([threat])
    allow(LinkSafety::DetectionRecorder).to receive(:record!)
    allow(LinkSafety::FinalContentGuard).to receive(:allow_once!)
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
      private_content: true,
      priority: :security,
    )
  end

  it "records a post-publish retry threat as disabled when the current mode is Enforce" do
    SiteSetting.link_safety_mode = "enforce"

    job.execute(target_type: "Post", target_id: 1, surface: "public_post", attempt: 1)

    expect(LinkSafety::DetectionRecorder).to have_received(:record!).with(
      hash_including(action: :disabled_after_publish, target: target),
    )
  end

  it "bridges an async clean result through the immediate rebake without reusable cache state" do
    clean = LinkSafety::Result.new(
      url: "https://example.com/",
      canonical_url: "https://example.com/",
      fingerprint: "c" * 64,
      host: "example.com",
      status: "clean",
      threat_types: [],
      provider: "web_risk_lookup",
      checked_at: Time.zone.now,
      expires_at: Time.zone.now,
      error_code: nil,
      source: "spec",
    )
    allow(LinkSafety::Checker).to receive(:check_many).and_return([clean])

    job.execute(target_type: "Post", target_id: 1, surface: "public_post", attempt: 1)

    expect(LinkSafety::FinalContentGuard).to have_received(:allow_once!).with(target, [clean.fingerprint])
    expect(job).to have_received(:rebake).with(target)
  end

  it "preserves actor, content hash and post revision when a provider error is retried again" do
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
        content_version: 7,
      ),
    )

    job.execute(
      target_type: "Post",
      target_id: 1,
      surface: "public_post",
      attempt: 1,
      actor_id: user.id,
      content_hash: "same-hash",
      content_version: 7,
    )
  end

  it "does not record, allow or rebake when content changes during the provider call" do
    allow(LinkSafety::RetryContext).to receive(:reload_matches_content?).and_return(false)

    job.execute(target_type: "Post", target_id: 1, surface: "public_post", attempt: 1)

    expect(LinkSafety::Checker).to have_received(:check_many)
    expect(LinkSafety::DetectionRecorder).not_to have_received(:record!)
    expect(LinkSafety::FinalContentGuard).not_to have_received(:allow_once!)
    expect(job).not_to have_received(:rebake)
  end

  it "binds a legacy retry to the execution-time content snapshot" do
    job.execute(target_type: "Post", target_id: 1, surface: "public_post", attempt: 1)

    expect(LinkSafety::RetryContext).to have_received(:reload_matches_content?).with(
      target,
      "guard-hash",
      expected_version: "guard-version",
    )
  end

  it "does no retry work when the target content changed after scheduling" do
    allow(LinkSafety::RetryContext).to receive(:matches_content?).with(
      target,
      "old-hash",
      expected_version: 4,
    ).and_return(false)

    job.execute(
      target_type: "Post",
      target_id: 1,
      surface: "public_post",
      attempt: 1,
      actor_id: user.id,
      content_hash: "old-hash",
      content_version: 4,
    )

    expect(LinkSafety::Checker).not_to have_received(:check_many)
  end

  it "does no retry work after the surface has been disabled" do
    allow(LinkSafety::SurfacePolicy).to receive(:enabled?).with(:public_post).and_return(false)

    job.execute(target_type: "Post", target_id: 1, surface: "public_post", attempt: 1)

    expect(LinkSafety::Checker).not_to have_received(:check_many)
  end
end
