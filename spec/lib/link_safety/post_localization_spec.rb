# frozen_string_literal: true

RSpec.describe "Link Safety PostLocalization integration" do
  fab!(:post) { Fabricate(:post) }
  fab!(:localizer) { Fabricate(:user) }

  before do
    SiteSetting.link_safety_enabled = true
    SiteSetting.link_safety_scan_public_posts = true
    allow(LinkSafety::PrivacyContext).to receive(:for_post).with(post).and_return(false)
  end

  it "validates localization raw with the localization actor and parent post surface" do
    raw = "translated [link](https://external.example/path)"
    localization =
      Fabricate.build(
        :post_localization,
        post: post,
        raw: raw,
        cooked: PrettyText.cook(raw),
        localizer_user_id: localizer.id,
      )
    extraction =
      LinkSafety::Extractor::Extraction.new(
        urls: ["https://external.example/path"],
        error_code: nil,
      )

    allow(LinkSafety::Extractor).to receive(:post_raw_result).with(
      raw,
      post.topic_id,
      user: localizer,
    ).and_return(extraction)
    allow(LinkSafety::ContentValidator).to receive(:validate_model!)

    expect(localization).to be_valid
    expect(LinkSafety::ContentValidator).to have_received(:validate_model!).with(
      model: localization,
      urls: extraction.urls,
      extraction_error: nil,
      surface: :public_post,
      user: localizer,
      private_content: false,
    )
  end

  it "persists the clean allowance and schedules the localization itself after a raw edit commits" do
    SiteSetting.link_safety_enabled = false
    localization =
      Fabricate(
        :post_localization,
        post: post,
        raw: "before",
        cooked: "<p>before</p>",
        localizer_user_id: localizer.id,
      )
    SiteSetting.link_safety_enabled = true

    allow(LinkSafety::ContentValidator).to receive(:validate_model!)
    allow(LinkSafety::FinalContentGuard).to receive(:persist_model_allowance!)
    allow(LinkSafety::PendingScheduler).to receive(:for_post_localization)

    localization.update!(raw: "after", cooked: "<p>after</p>")

    expect(LinkSafety::FinalContentGuard).to have_received(:persist_model_allowance!).with(localization)
    expect(LinkSafety::PendingScheduler).to have_received(:for_post_localization).with(localization)
  end
end
