# frozen_string_literal: true

RSpec.describe LinkSafety::PendingScheduler do
  before do
    SiteSetting.link_safety_enabled = true
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    allow(LinkSafety::SurfacePolicy).to receive(:enabled?).and_return(true)
  end

  it "uses the post editor when recooking content for pending detection" do
    editor = Fabricate(:user)
    post = double(
      "post",
      raw: "raw",
      topic_id: 42,
      id: 99,
      topic: double("topic", private_message?: false),
    )
    extraction = LinkSafety::Extractor::Extraction.new(urls: [], error_code: nil)

    allow(LinkSafety::ActorResolver).to receive(:for_post).with(post).and_return(editor)
    allow(LinkSafety::Extractor).to receive(:post_raw_result).and_return(extraction)
    allow(described_class).to receive(:schedule)

    described_class.for_post(post)

    expect(LinkSafety::Extractor).to have_received(:post_raw_result).with("raw", 42, user: editor)
    expect(described_class).to have_received(:schedule).with(
      target_type: "Post",
      target_id: 99,
      urls: [],
      surface: :public_post,
      actor_id: editor.id,
      content_hash: LinkSafety::RetryContext.content_hash("raw"),
    )
  end

  it "does not schedule a retry for an internal relative URL" do
    expect(Jobs).not_to receive(:enqueue_in)

    described_class.schedule(
      target_type: "Post",
      target_id: 99,
      urls: ["/t/topic/1"],
      surface: :public_post,
    )
  end
end
