# frozen_string_literal: true

RSpec.describe LinkSafety::Providers::Base do
  let(:provider) { described_class.new }

  it "only classifies availability failures as circuit-breaker-transient" do
    expect(provider.transient_failure?(:read_timeout)).to eq(true)
    expect(provider.transient_failure?(:http_429)).to eq(true)
    expect(provider.transient_failure?(:http_503)).to eq(true)

    expect(provider.transient_failure?(:http_400)).to eq(false)
    expect(provider.transient_failure?(:http_403)).to eq(false)
    expect(provider.transient_failure?(:malformed_response)).to eq(false)
    expect(provider.transient_failure?(:provider_internal_error)).to eq(false)
  end
end
