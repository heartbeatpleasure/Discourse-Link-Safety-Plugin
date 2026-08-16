# frozen_string_literal: true

RSpec.describe LinkSafety::VerificationPolicy do
  before { SiteSetting.link_safety_mode = "enforce" }

  it "fails closed on security-control integrity failures even when provider outages are configured fail-open" do
    expect(described_class.block_errors?(["canonicalization_failure"], failure_policy: :fail_open)).to eq(true)
    expect(described_class.block_errors?(["validation_budget_exceeded"], failure_policy: :fail_open)).to eq(true)
    expect(described_class.block_errors?(["malformed_response"], failure_policy: :fail_open)).to eq(true)
    expect(described_class.block_errors?(["provider_internal_error"], failure_policy: :fail_open)).to eq(true)
  end

  it "keeps transient provider outages under the administrator-selected failure policy" do
    expect(described_class.block_errors?(["read_timeout"], failure_policy: :fail_open)).to eq(false)
    expect(described_class.block_errors?(["read_timeout"], failure_policy: :fail_closed)).to eq(true)
  end

  it "fails closed on provider authentication and request-contract failures" do
    expect(described_class.block_errors?(["http_400"], failure_policy: :fail_open)).to eq(true)
    expect(described_class.block_errors?(["http_401"], failure_policy: :fail_open)).to eq(true)
    expect(described_class.block_errors?(["http_403"], failure_policy: :fail_open)).to eq(true)
    expect(described_class.block_errors?(["http_404"], failure_policy: :fail_open)).to eq(true)
    expect(described_class.block_errors?(["http_302"], failure_policy: :fail_open)).to eq(true)
  end
  it "treats local lookup budget exhaustion and stale provider data as hard failures in Enforce" do
    SiteSetting.link_safety_mode = "enforce"
    %w[user_lookup_rate_limited global_lookup_rate_limited lookup_budget_unavailable stale_provider_response unsupported_threat_type].each do |code|
      expect(described_class.block_errors?([code], failure_policy: :fail_open)).to eq(true)
    end
  end

end
