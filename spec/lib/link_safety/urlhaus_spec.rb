# frozen_string_literal: true

RSpec.describe LinkSafety::Providers::Urlhaus do
  let(:provider) { described_class.new }
  let(:item) { LinkSafety::Canonicalizer.call("https://example.com/path") }

  before do
    SiteSetting.link_safety_urlhaus_enabled = true
    SiteSetting.link_safety_urlhaus_auth_key = "test-key"
    allow(LinkSafety::Statistics).to receive(:bump!)
    allow(LinkSafety::CircuitBreaker).to receive(:open?).and_return(false)
    allow(LinkSafety::CircuitBreaker).to receive(:record_success)
    allow(LinkSafety::CircuitBreaker).to receive(:record_failure)
    allow(LinkSafety::HealthRegistry).to receive(:success!)
    allow(LinkSafety::HealthRegistry).to receive(:failure!)
  end

  def http_ok(payload)
    response = Net::HTTPOK.new("1.1", "200", "OK")
    response.body = payload.to_json
    response
  end

  it "sends a non-default port in the URLhaus full-URL lookup body" do
    port_item = LinkSafety::Canonicalizer.call("https://example.com:8443/path")
    expect(provider).to receive(:request) do |_uri, body:, **_options|
      expect(URI.decode_www_form(body)).to include(["url", "https://example.com:8443/path"])
      [http_ok({ query_status: "no_results" }), 10]
    end

    expect(provider.check(port_item).status).to eq("clean")
  end

  it "returns a typed clean response with a bounded negative TTL" do
    allow(provider).to receive(:request).and_return([http_ok({ query_status: "no_results" }), 10])
    result = provider.check(item)
    expect(result.status).to eq("clean")
    expect(result.expires_at).to be_within(2.seconds).of(1.hour.from_now)
  end

  it "returns a typed threat response with its own positive TTL" do
    allow(provider).to receive(:request).and_return(
      [http_ok({ query_status: "ok", threat: "malware_download" }), 10],
    )
    result = provider.check(item)
    expect(result.status).to eq("threat")
    expect(result.threat_types).to eq(["MALWARE_DISTRIBUTION"])
    expect(result.expires_at).to be_within(2.seconds).of(12.hours.from_now)
  end

  it "does not silently treat provider failure as clean" do
    allow(provider).to receive(:request).and_return([nil, nil, :read_timeout])
    result = provider.check(item)
    expect(result.status).to eq("error")
    expect(result.error_code).to eq("read_timeout")
  end

  it "reports an enabled provider with no Auth-Key as a configuration error" do
    SiteSetting.link_safety_urlhaus_auth_key = ""
    result = provider.check(item)
    expect(result.status).to eq("error")
    expect(result.error_code).to eq("missing_urlhaus_auth_key")
  end
end
