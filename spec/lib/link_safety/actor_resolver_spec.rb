# frozen_string_literal: true

RSpec.describe LinkSafety::ActorResolver do
  fab!(:author) { Fabricate(:user) }
  fab!(:editor) { Fabricate(:user) }

  it "uses the last editor for a post" do
    post = double("post", last_editor: editor, user: author, acting_user: author)
    expect(described_class.for_post(post)).to eq(editor)
  end

  it "prefers an explicit PostCreator acting user over the nominal author" do
    post = double("post", last_editor: author, user: author, acting_user: editor)
    expect(described_class.for_post(post)).to eq(editor)
  end

  it "uses the original author when a post has no last editor" do
    post = double("post", last_editor: nil, user: author, acting_user: author)
    expect(described_class.for_post(post)).to eq(author)
  end

  it "uses the last editor for a Chat message" do
    message = double("message", last_editor: editor, user: author)
    expect(described_class.for_chat_message(message)).to eq(editor)
  end

  it "uses a Topic acting user when Discourse exposes one" do
    topic = double("topic", acting_user: editor, user: author, new_record?: false)
    expect(described_class.for_topic(topic)).to eq(editor)
  end

  it "uses the author as the reliable actor for a new Topic" do
    topic = double("topic", acting_user: nil, user: author, new_record?: true)
    expect(described_class.for_topic(topic)).to eq(author)
  end

  it "does not blame the original author for an existing Topic edit without an acting user" do
    topic = double("topic", acting_user: nil, user: author, new_record?: false)
    expect(described_class.for_topic(topic)).to be_nil
  end
end
