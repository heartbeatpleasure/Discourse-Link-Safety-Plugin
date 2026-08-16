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
    allow(LinkSafety::Statistics).to receive(:bump!)
  end

  def result(status)
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
      error_code: status == "error" ? "read_timeout" : nil,
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

    expect(model.errors[:base]).to include(I18n.t("link_safety.errors.malicious_link"))
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

end
