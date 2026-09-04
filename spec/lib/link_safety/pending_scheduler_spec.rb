# frozen_string_literal: true

RSpec.describe LinkSafety::PendingScheduler do
  before do
    SiteSetting.link_safety_enabled = true
    SiteSetting.link_safety_provider = "safe_browsing_v5"
    allow(LinkSafety::SurfacePolicy).to receive(:enabled?).and_return(true)
  end

  it "carries immutable actor/content context into a post retry" do
    editor = Fabricate(:user)
    post = double("post", id: 99)
    extraction = LinkSafety::Extractor::Extraction.new(urls: [], error_code: nil)
    context = LinkSafety::TargetContext::Context.new(
      surface: :public_post, actor: editor, private_content: false, extraction: extraction,
    )

    allow(LinkSafety::TargetContext).to receive(:for).with(post).and_return(context)
    allow(LinkSafety::RetryContext).to receive(:content_hash_for).with(post).and_return("hash")
    allow(LinkSafety::RetryContext).to receive(:content_version_for).with(post).and_return(7)
    allow(described_class).to receive(:schedule)

    described_class.for_post(post)

    expect(described_class).to have_received(:schedule).with(
      target_type: "Post",
      target_id: 99,
      urls: [],
      surface: :public_post,
      actor_id: editor.id,
      content_hash: "hash",
      content_version: 7,
    )
  end

  it "schedules a post localization with its own target id, actor and content identity" do
    localizer = Fabricate(:user)
    localization = double("post localization", id: 88)
    extraction = LinkSafety::Extractor::Extraction.new(urls: [], error_code: nil)
    context = LinkSafety::TargetContext::Context.new(
      surface: :public_post, actor: localizer, private_content: false, extraction: extraction,
    )

    allow(LinkSafety::TargetContext).to receive(:for).with(localization).and_return(context)
    allow(LinkSafety::RetryContext).to receive(:content_hash_for).with(localization).and_return("loc-hash")
    allow(LinkSafety::RetryContext).to receive(:content_version_for).with(localization).and_return(
      "2026-09-04T20:00:00.000000Z",
    )
    allow(described_class).to receive(:schedule)

    described_class.for_post_localization(localization)

    expect(described_class).to have_received(:schedule).with(
      target_type: "PostLocalization",
      target_id: 88,
      urls: [],
      surface: :public_post,
      actor_id: localizer.id,
      content_hash: "loc-hash",
      content_version: "2026-09-04T20:00:00.000000Z",
    )
  end

  it "carries a chat updated_at content version into a retry" do
    editor = Fabricate(:user)
    message = double("chat message", id: 77)
    extraction = LinkSafety::Extractor::Extraction.new(urls: [], error_code: nil)
    context = LinkSafety::TargetContext::Context.new(
      surface: :chat_public, actor: editor, private_content: false, extraction: extraction,
    )

    allow(LinkSafety::TargetContext).to receive(:for).with(message).and_return(context)
    allow(LinkSafety::RetryContext).to receive(:content_hash_for).with(message).and_return("chat-hash")
    allow(LinkSafety::RetryContext).to receive(:content_version_for).with(message).and_return("2026-08-24T21:00:00.000000Z")
    allow(described_class).to receive(:schedule)

    described_class.for_chat_message(message)

    expect(described_class).to have_received(:schedule).with(
      target_type: "Chat::Message",
      target_id: 77,
      urls: [],
      surface: :chat_public,
      actor_id: editor.id,
      content_hash: "chat-hash",
      content_version: "2026-08-24T21:00:00.000000Z",
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
