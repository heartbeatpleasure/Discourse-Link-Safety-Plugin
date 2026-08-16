# frozen_string_literal: true

RSpec.describe LinkSafety::ContentValidator do
  class LinkSafetyValidationTestModel
    include ActiveModel::Validations
  end

  let(:model) { LinkSafetyValidationTestModel.new }
  fab!(:user) { Fabricate(:user) }

  before do
    SiteSetting.link_safety_max_external_urls_per_submission = 50
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    allow(LinkSafety::DetectionRecorder).to receive(:record!)
    allow(LinkSafety::DetectionRecorder).to receive(:queue_blocked!)
    allow(LinkSafety::Statistics).to receive(:bump!)
  end

  def result(status, error_code: nil)
    LinkSafety::Result.new(
      url: "https://example.com/",
      canonical_url: "https://example.com/",
      fingerprint: "a" * 64,
      host: "example.com",
      status: status,
      threat_types: status == "threat" ? ["MALWARE"] : [],
      provider: "safe_browsing_v5",
      checked_at: Time.zone.now,
      expires_at: 5.minutes.from_now,
      error_code: status == "error" ? (error_code || "read_timeout") : nil,
      source: "spec",
    )
  end

  it "does not block a confirmed threat in monitor mode" do
    SiteSetting.link_safety_mode = "monitor"
    allow(LinkSafety::Checker).to receive(:check_many).and_return([result("threat")])

    described_class.validate_model!(model: model, urls: ["https://example.com/"], surface: :public_post, user: user)

    expect(model.errors).to be_empty
    expect(LinkSafety::DetectionRecorder).to have_received(:record!).with(hash_including(action: :monitor_only))
  end

  it "blocks a confirmed threat in enforce mode" do
    SiteSetting.link_safety_mode = "enforce"
    allow(LinkSafety::Checker).to receive(:check_many).and_return([result("threat")])

    described_class.validate_model!(model: model, urls: ["https://example.com/"], surface: :public_post, user: user)

    expect(model.errors[:base].join(" ")).to include("Advisory provided by Google")
    expect(LinkSafety::DetectionRecorder).to have_received(:queue_blocked!).with(
      hash_including(model: model, surface: :public_post, user: user)
    ).once
    expect(LinkSafety::DetectionRecorder).not_to have_received(:record!).with(
      hash_including(action: :blocked_before_save)
    )
  end

  it "fails open on provider errors by default" do
    SiteSetting.link_safety_failure_policy = "fail_open"
    allow(LinkSafety::Checker).to receive(:check_many).and_return([result("error")])

    described_class.validate_model!(model: model, urls: ["https://example.com/"], surface: :public_post, user: user)

    expect(model.errors).to be_empty
  end

  it "can fail closed on provider errors" do
    SiteSetting.link_safety_failure_policy = "fail_closed"
    allow(LinkSafety::Checker).to receive(:check_many).and_return([result("error")])

    described_class.validate_model!(model: model, urls: ["https://example.com/"], surface: :public_post, user: user)

    expect(model.errors[:base]).to include(I18n.t("link_safety.errors.unavailable"))
  end
  it "accepts an explicit fail-closed override for profile-like flows" do
    SiteSetting.link_safety_failure_policy = "fail_open"
    allow(LinkSafety::Checker).to receive(:check_many).and_return([result("error")])

    described_class.validate_model!(
      model: model,
      urls: ["https://example.com/"],
      surface: :profile,
      user: user,
      failure_policy: :fail_closed,
    )

    expect(model.errors[:base]).to include(I18n.t("link_safety.errors.unavailable"))
  end

  it "fails closed on canonicalization integrity failures in enforce mode even when provider outages fail open" do
    SiteSetting.link_safety_mode = "enforce"
    SiteSetting.link_safety_failure_policy = "fail_open"

    described_class.validate_model!(
      model: model,
      urls: [],
      extraction_error: "extractor_failure",
      surface: :public_post,
      user: user,
    )

    expect(model.errors[:base]).to include(I18n.t("link_safety.errors.unavailable"))
  end

  it "fails closed when the validation budget is exhausted in enforce mode" do
    SiteSetting.link_safety_mode = "enforce"
    SiteSetting.link_safety_failure_policy = "fail_open"
    allow(LinkSafety::Checker).to receive(:check_many).and_return(
      [result("error", error_code: "validation_budget_exceeded")],
    )

    described_class.validate_model!(model: model, urls: ["https://example.com/"], surface: :public_post, user: user)

    expect(model.errors[:base]).to include(I18n.t("link_safety.errors.unavailable"))
  end

  it "still permits a transient provider timeout when enforce mode explicitly uses fail-open" do
    SiteSetting.link_safety_mode = "enforce"
    SiteSetting.link_safety_failure_policy = "fail_open"
    allow(LinkSafety::Checker).to receive(:check_many).and_return([result("error", error_code: "read_timeout")])

    described_class.validate_model!(model: model, urls: ["https://example.com/"], surface: :public_post, user: user)

    expect(model.errors).to be_empty
  end

  it "rejects an excessive raw URL candidate set before invoking the checker" do
    urls = 201.times.map { |i| "https://example#{i}.com/" }
    expect(LinkSafety::Checker).not_to receive(:check_many)

    described_class.validate_model!(model: model, urls: urls, surface: :public_post, user: user)

    expect(model.errors[:base]).to include(I18n.t("link_safety.errors.too_many_links"))
  end

end
