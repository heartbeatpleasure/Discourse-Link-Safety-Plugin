# frozen_string_literal: true

RSpec.describe LinkSafety::RedisNamespace do
  it "changes Redis keys with the active multisite database" do
    allow(RailsMultisite::ConnectionManagement).to receive(:current_db).and_return("site_a")
    first = described_class.key("health", "provider")
    allow(RailsMultisite::ConnectionManagement).to receive(:current_db).and_return("site_b")
    second = described_class.key("health", "provider")

    expect(first).to eq("link_safety:site_a:health:provider")
    expect(second).to eq("link_safety:site_b:health:provider")
    expect(first).not_to eq(second)
  end
end
