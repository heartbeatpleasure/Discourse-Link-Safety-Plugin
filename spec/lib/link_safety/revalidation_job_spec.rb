# frozen_string_literal: true

RSpec.describe Jobs::LinkSafetyRevalidateContent do
  fab!(:user) { Fabricate(:user) }

  it "walks UserProfile targets with the user_id cursor" do
    profile = user.user_profile
    profile.update_columns(website: "https://external.example/profile")
    cursor_name = "spec_user_profiles"
    cursor_key = LinkSafety::RedisNamespace.key("revalidation_cursor", cursor_name)
    Discourse.redis.del(cursor_key)

    result = LinkSafety::FinalContentVerifier::Result.new(checked: 1, threats: [], errors: [])
    allow(LinkSafety::FinalContentVerifier).to receive(:verify!).and_return(result)

    described_class.new.send(
      :process_scope,
      scope: UserProfile.where(user_id: profile.user_id),
      cursor_name: cursor_name,
      cursor_column: :user_id,
      limit: 10,
    )

    expect(LinkSafety::FinalContentVerifier).to have_received(:verify!).with(profile, revalidation: true)
    expect(Discourse.redis.get(cursor_key).to_i).to eq(profile.user_id)
  ensure
    Discourse.redis.del(cursor_key) if cursor_key
  end

  it "qualifies the cursor column for joined Post scopes" do
    post = Fabricate(:post, user: user)
    cursor_name = "spec_joined_posts"
    cursor_key = LinkSafety::RedisNamespace.key("revalidation_cursor", cursor_name)
    Discourse.redis.del(cursor_key)

    result = LinkSafety::FinalContentVerifier::Result.new(checked: 1, threats: [], errors: [])
    allow(LinkSafety::FinalContentVerifier).to receive(:verify!).and_return(result)

    described_class.new.send(
      :process_scope,
      scope: Post.where(id: post.id).joins(:topic),
      cursor_name: cursor_name,
      cursor_column: :id,
      limit: 10,
    )

    expect(LinkSafety::FinalContentVerifier).to have_received(:verify!).with(post, revalidation: true)
    expect(Discourse.redis.get(cursor_key).to_i).to eq(post.id)
  ensure
    Discourse.redis.del(cursor_key) if cursor_key
  end
end
