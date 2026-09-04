# frozen_string_literal: true

RSpec.describe Jobs::LinkSafetyVerifyRenderedTarget do
  fab!(:user) { Fabricate(:user) }

  it "loads PostLocalization targets by their independent id" do
    SiteSetting.link_safety_enabled = false
    localization = Fabricate(:post_localization)
    SiteSetting.link_safety_enabled = true

    expect(described_class.new.send(:find_target, "PostLocalization", localization.id)).to eq(localization)
  end

  it "loads UserProfile targets by their user_id primary key" do
    profile = user.user_profile

    expect(described_class.new.send(:find_target, "UserProfile", profile.user_id)).to eq(profile)
  end
  it "discards a final verification job when the target content changed" do
    SiteSetting.link_safety_enabled = true
    profile = user.user_profile
    job = described_class.new
    allow(job).to receive(:find_target).and_return(profile)
    allow(LinkSafety::RetryContext).to receive(:matches_content?).with(
      profile,
      "old-hash",
      expected_version: nil,
    ).and_return(false)
    allow(LinkSafety::FinalContentVerifier).to receive(:verify!)
    allow(LinkSafety::FinalContentVerifier).to receive(:release_schedule)

    job.execute(
      target_type: "UserProfile",
      target_id: profile.user_id,
      attempt: 1,
      revalidation: true,
      content_hash: "old-hash",
      content_version: nil,
    )

    expect(LinkSafety::FinalContentVerifier).not_to have_received(:verify!)
    expect(LinkSafety::FinalContentVerifier).to have_received(:release_schedule).with(
      profile,
      content_hash: "old-hash",
      content_version: nil,
    )
  end

end
