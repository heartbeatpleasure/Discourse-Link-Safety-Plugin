# frozen_string_literal: true

RSpec.describe LinkSafety::RetryContext do
  fab!(:author) { Fabricate(:user) }
  fab!(:actor) { Fabricate(:user) }

  it "creates a stable SHA-256 identity for content" do
    expect(described_class.content_hash("same content")).to eq(described_class.content_hash("same content"))
    expect(described_class.content_hash("same content")).not_to eq(described_class.content_hash("changed content"))
  end

  it "rejects a retry context after post content changes" do
    post = Post.new(raw: "new content", user: author)
    old_hash = described_class.content_hash("old content")

    expect(described_class.matches_content?(post, old_hash)).to eq(false)
  end

  it "accepts legacy jobs that have no content hash" do
    post = Post.new(raw: "content", user: author)

    expect(described_class.matches_content?(post, nil)).to eq(true)
  end

  it "does not fall back to the content owner when a scheduled actor no longer exists" do
    post = Post.new(raw: "checked content", user: author)
    content_hash = described_class.content_hash(post.raw)

    resolved = described_class.actor_for(post, actor_id: 9_999_999_999, expected_hash: content_hash)

    expect(resolved).to be_nil
  end

  it "uses the scheduled actor only while the exact scheduled content is still present" do
    post = Post.new(raw: "checked content", user: author)
    content_hash = described_class.content_hash(post.raw)

    resolved = described_class.actor_for(post, actor_id: actor.id, expected_hash: content_hash)

    expect(resolved).to eq(actor)
  end
end
