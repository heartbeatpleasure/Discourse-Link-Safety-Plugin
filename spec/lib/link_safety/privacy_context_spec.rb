# frozen_string_literal: true

RSpec.describe LinkSafety::PrivacyContext do
  before { allow(SiteSetting).to receive(:login_required).and_return(false) }

  it "treats a post in a read-restricted category as private provider content" do
    category = double("category", read_restricted?: true)
    topic = double("topic", private_message?: false, category: category)
    post = double("post", whisper?: false, topic: topic)
    expect(described_class.for_post(post)).to eq(true)
  end

  it "treats hidden posts and unlisted topics as private provider content" do
    visible_topic = double("topic", visible: true, private_message?: false, category: nil)
    hidden_post = double("post", whisper?: false, hidden?: true, topic: visible_topic)
    expect(described_class.for_post(hidden_post)).to eq(true)

    hidden_topic = double("topic", visible: false, private_message?: false, category: nil)
    post = double("post", whisper?: false, hidden?: false, topic: hidden_topic)
    expect(described_class.for_post(post)).to eq(true)
    expect(described_class.for_topic(hidden_topic)).to eq(true)
  end

  it "treats whispers as private provider content" do
    topic = double("topic", private_message?: false, category: nil)
    post = double("post", whisper?: true, topic: topic)
    expect(described_class.for_post(post)).to eq(true)
  end

  it "treats restricted category Chat as private even when it is not a DM" do
    channel = double("channel", chatable_type: "Category", read_restricted?: true)
    message = double("message", chat_channel: channel)
    allow(Chat::Channel).to receive(:direct_channel_chatable_types).and_return(["DirectMessage"])
    expect(described_class.for_chat_message(message)).to eq(true)
  end

  it "conservatively treats resolution errors as private" do
    post = double("post")
    allow(post).to receive(:whisper?).and_raise(StandardError)
    expect(described_class.for_post(post)).to eq(true)
  end
  it "uses Discourse anonymous profile visibility for provider privacy" do
    user = double("user")
    profile = double("profile", user: user)
    guardian = double("guardian")
    allow(Guardian).to receive(:new).and_return(guardian)
    allow(guardian).to receive(:can_see_profile?).with(user).and_return(false)

    expect(described_class.for_user_profile(profile)).to eq(true)
  end

end
