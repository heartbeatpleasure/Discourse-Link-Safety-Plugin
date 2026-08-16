# frozen_string_literal: true

RSpec.describe LinkSafety::Statistics do
  before do
    LinkSafety::DailyStat.delete_all
  end

  it "persists ordinary counters" do
    described_class.bump!("safe_browsing_v5", checks: 2, provider_calls: 1, threats: 1, monitored: 1)

    row = LinkSafety::DailyStat.find_by!(stat_date: Date.current, provider: "safe_browsing_v5")
    expect(row.checks).to eq(2)
    expect(row.provider_calls).to eq(1)
    expect(row.threats).to eq(1)
    expect(row.monitored).to eq(1)
  end

  it "maps the public errors counter to the ActiveRecord-safe error_count column" do
    described_class.bump!("safe_browsing_v5", errors: 2)

    row = LinkSafety::DailyStat.find_by!(stat_date: Date.current, provider: "safe_browsing_v5")
    expect(row.error_count).to eq(2)
  end
end
