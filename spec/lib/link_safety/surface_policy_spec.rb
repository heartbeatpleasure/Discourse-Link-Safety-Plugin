# frozen_string_literal: true

RSpec.describe LinkSafety::SurfacePolicy do
  before do
    SiteSetting.link_safety_enabled = true
    SiteSetting.link_safety_scan_public_posts = true
    SiteSetting.link_safety_scan_private_messages = true
    SiteSetting.link_safety_scan_chat_public = true
    SiteSetting.link_safety_scan_chat_direct_messages = true
    SiteSetting.link_safety_scan_profile_links = true
    SiteSetting.link_safety_scan_topic_featured_links = true
    SiteSetting.link_safety_scan_group_bio_links = true
  end

  it "uses the current site settings for every content surface" do
    expect(described_class.enabled?(:public_post)).to eq(true)
    SiteSetting.link_safety_scan_public_posts = false
    expect(described_class.enabled?(:public_post)).to eq(false)

    expect(described_class.enabled?(:private_message)).to eq(true)
    SiteSetting.link_safety_scan_private_messages = false
    expect(described_class.enabled?(:private_message)).to eq(false)

    expect(described_class.enabled?(:chat_public)).to eq(true)
    SiteSetting.link_safety_scan_chat_public = false
    expect(described_class.enabled?(:chat_public)).to eq(false)

    expect(described_class.enabled?(:chat_dm)).to eq(true)
    SiteSetting.link_safety_scan_chat_direct_messages = false
    expect(described_class.enabled?(:chat_dm)).to eq(false)

    expect(described_class.enabled?(:profile)).to eq(true)
    SiteSetting.link_safety_scan_profile_links = false
    expect(described_class.enabled?(:profile)).to eq(false)

    expect(described_class.enabled?(:topic_featured_link)).to eq(true)
    SiteSetting.link_safety_scan_topic_featured_links = false
    expect(described_class.enabled?(:topic_featured_link)).to eq(false)

    expect(described_class.enabled?(:group_profile)).to eq(true)
    SiteSetting.link_safety_scan_group_bio_links = false
    expect(described_class.enabled?(:group_profile)).to eq(false)
  end

  it "disables all surface work when Link Safety is disabled" do
    SiteSetting.link_safety_enabled = false
    expect(described_class.enabled?(:public_post)).to eq(false)
    expect(described_class.enabled?(:chat_dm)).to eq(false)
    expect(described_class.enabled?(:admin_test)).to eq(false)
  end

  it "never enables an unknown surface" do
    expect(described_class.enabled?(:unknown_surface)).to eq(false)
  end
end
