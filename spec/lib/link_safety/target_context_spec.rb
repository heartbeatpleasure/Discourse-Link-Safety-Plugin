# frozen_string_literal: true

RSpec.describe LinkSafety::TargetContext do
  fab!(:user) { Fabricate(:user) }

  before do
    allow(LinkSafety::PrivacyContext).to receive(:for_user_profile).and_return(false)
    allow(LinkSafety::PrivacyContext).to receive(:for_topic).and_return(false)
    allow(LinkSafety::PrivacyContext).to receive(:for_group).and_return(false)
  end

  it "extracts both website and bio links from a user profile" do
    profile = UserProfile.new(user: user, website: "https://website.example", bio_raw: "bio")
    allow(LinkSafety::Extractor).to receive(:markdown_result).with("bio").and_return(
      LinkSafety::Extractor::Extraction.new(urls: ["https://bio.example"], error_code: nil),
    )

    context = described_class.for(profile)

    expect(context.surface).to eq(:profile)
    expect(context.actor).to eq(user)
    expect(context.extraction.urls).to contain_exactly(
      "https://website.example",
      "https://bio.example",
    )
  end

  it "does not attribute periodic topic featured-link checks to the topic author" do
    topic = Topic.new(user: user, featured_link: "https://featured.example")

    context = described_class.for(topic)

    expect(context.surface).to eq(:topic_featured_link)
    expect(context.actor).to be_nil
    expect(context.extraction.urls).to eq(["https://featured.example"])
  end

  it "extracts group bio links without inventing an actor" do
    group = Group.new(bio_raw: "group bio")
    allow(LinkSafety::Extractor).to receive(:markdown_result).with("group bio").and_return(
      LinkSafety::Extractor::Extraction.new(urls: ["https://group.example"], error_code: nil),
    )

    context = described_class.for(group)

    expect(context.surface).to eq(:group_profile)
    expect(context.actor).to be_nil
    expect(context.extraction.urls).to eq(["https://group.example"])
  end

  it "treats a post localization as an independent target while inheriting the parent surface and privacy" do
    localizer = Fabricate(:user)
    post = Fabricate(:post, user: user)
    localization =
      Fabricate(:post_localization, post: post, raw: "localized raw", localizer_user_id: localizer.id)
    extraction =
      LinkSafety::Extractor::Extraction.new(urls: ["https://localized.example"], error_code: nil)

    allow(LinkSafety::PrivacyContext).to receive(:for_post).with(post).and_return(true)
    allow(LinkSafety::Extractor).to receive(:post_raw_result).with(
      localization.raw,
      post.topic_id,
      user: localizer,
    ).and_return(extraction)

    context = described_class.for(localization)

    expect(context.surface).to eq(:public_post)
    expect(context.actor).to eq(localizer)
    expect(context.private_content).to eq(true)
    expect(context.extraction.urls).to eq(["https://localized.example"])
  end
end
