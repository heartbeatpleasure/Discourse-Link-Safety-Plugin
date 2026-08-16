# frozen_string_literal: true

RSpec.describe LinkSafety::DetectionRecorder do
  class LinkSafetyBlockedQueueTestModel
    attr_accessor :id
  end

  fab!(:user) { Fabricate(:user) }
  let(:model) { LinkSafetyBlockedQueueTestModel.new }
  let(:result) do
    LinkSafety::Result.new(
      url: "https://example.com/",
      canonical_url: "https://example.com/",
      fingerprint: "b" * 64,
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

  it "queues a blocked attempt once and counts it before transaction finalization" do
    allow(LinkSafety::Statistics).to receive(:bump!)

    2.times do
      described_class.queue_blocked!(
        model: model,
        result: result,
        surface: :public_post,
        user: user,
      )
    end

    expect(LinkSafety::Statistics).to have_received(:bump!).with(
      "safe_browsing_v5",
      threats: 1,
      blocked: 1,
    ).once
    expect(described_class.take_queued!(model).length).to eq(1)
  end

  it "flushes queued entries without counting them twice" do
    allow(LinkSafety::Statistics).to receive(:bump!)
    allow(described_class).to receive(:record!).and_return(nil)

    described_class.queue_blocked!(
      model: model,
      result: result,
      surface: :public_post,
      user: user,
    )
    entries = described_class.take_queued!(model)
    described_class.flush_entries!(entries, target: model)

    expect(described_class).to have_received(:record!).with(
      result: result,
      surface: "public_post",
      user: user,
      action: :blocked_before_save,
      target: model,
      count_statistics: false,
    ).once
  end
end
