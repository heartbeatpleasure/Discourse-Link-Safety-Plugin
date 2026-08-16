# frozen_string_literal: true

RSpec.describe LinkSafety::LookupBudget do
  fab!(:user) { Fabricate(:user) }

  before do
    SiteSetting.link_safety_lookup_budget_per_user_10_minutes = 100
    SiteSetting.link_safety_lookup_budget_global_per_minute = 1000
    clear_budget_keys
  end

  after { clear_budget_keys }

  def clear_budget_keys
    Discourse.redis.del(described_class.send(:window_key, "global", described_class::GLOBAL_WINDOW_SECONDS))
    Discourse.redis.del(described_class.send(:window_key, "user:#{user.id}", described_class::USER_WINDOW_SECONDS))
  end

  it "allows work within both budgets" do
    result = described_class.reserve(user: user, units: 10)
    expect(result.allowed?).to eq(true)
    expect(result.error_code).to be_nil
  end

  it "rejects a user that exceeds the weighted per-user budget" do
    expect(described_class.reserve(user: user, units: 100).allowed?).to eq(true)
    result = described_class.reserve(user: user, units: 1)

    expect(result.allowed?).to eq(false)
    expect(result.error_code).to eq("user_lookup_rate_limited")
  end

  it "applies the global budget to background work without a user" do
    SiteSetting.link_safety_lookup_budget_global_per_minute = 100
    expect(described_class.reserve(user: nil, units: 100).allowed?).to eq(true)
    result = described_class.reserve(user: nil, units: 1)

    expect(result.allowed?).to eq(false)
    expect(result.error_code).to eq("global_lookup_rate_limited")
  end
end
