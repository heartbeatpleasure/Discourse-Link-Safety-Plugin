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
    expect(provider.transient_failure?(:response_too_large)).to eq(false)
    expect(provider.transient_failure?(:provider_internal_error)).to eq(false)
  end

  it "rejects a declared response body larger than the hard limit before reading it" do
    response = Net::HTTPOK.new("1.1", "200", "OK")
    response["Content-Length"] = (described_class::MAX_RESPONSE_BYTES + 1).to_s

    expect {
      provider.send(:enforce_content_length!, response)
    }.to raise_error(described_class::ResponseTooLarge)
  end
end
