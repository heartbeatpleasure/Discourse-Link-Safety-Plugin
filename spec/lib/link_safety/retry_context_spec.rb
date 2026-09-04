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
  it "uses updated_at as a stable content version for non-post targets" do
    timestamp = Time.utc(2026, 8, 24, 21, 42, 13, 123_456)
    target = double("target", updated_at: timestamp)

    expect(described_class.content_version_for(target)).to eq(timestamp.iso8601(6))
  end

  it "reloads persisted content before accepting a provider response" do
    group = Group.new(name: "security-group", bio_raw: "before")
    allow(group).to receive(:persisted?).and_return(true)
    allow(group).to receive(:reload) do
      group.bio_raw = "after"
      group
    end
    old_hash = described_class.content_hash("before")

    expect(described_class.reload_matches_content?(group, old_hash)).to eq(false)
  end

  it "binds post localization identity to localization raw rather than parent post raw" do
    post = Fabricate(:post, raw: "parent content")
    localization = Fabricate(:post_localization, post: post, raw: "translation one")
    first = described_class.content_hash_for(localization)

    localization.raw = "translation two"

    expect(described_class.content_hash_for(localization)).not_to eq(first)
    expect(described_class.content_hash_for(localization)).to eq(
      described_class.content_hash("translation two"),
    )
  end

  it "uses a post localization updated_at as its independent content version" do
    timestamp = Time.utc(2026, 9, 4, 20, 15, 30, 123_456)
    localization = Fabricate.build(:post_localization)
    allow(localization).to receive(:updated_at).and_return(timestamp)

    expect(described_class.content_version_for(localization)).to eq(timestamp.iso8601(6))
  end

  it "binds profile allowances/revalidation to both website and bio content" do
    profile = UserProfile.new(user: author, website: "https://example.com", bio_raw: "first")
    first = described_class.content_hash_for(profile)
    profile.bio_raw = "second"

    expect(described_class.content_hash_for(profile)).not_to eq(first)
  end

end
