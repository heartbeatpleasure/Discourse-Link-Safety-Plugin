# frozen_string_literal: true

RSpec.describe LinkSafety::Providers::GoogleWebRisk do
  let(:provider) { described_class.new }

  before do
    SiteSetting.link_safety_google_api_key = "test-key"
    SiteSetting.link_safety_google_user_protection_notice_acknowledged = true
    SiteSetting.link_safety_validation_budget_ms = 3000
    allow(LinkSafety::Statistics).to receive(:bump!)
    allow(LinkSafety::CircuitBreaker).to receive(:record_success)
    allow(LinkSafety::CircuitBreaker).to receive(:record_failure)
    allow(LinkSafety::HealthRegistry).to receive(:success!)
    allow(LinkSafety::HealthRegistry).to receive(:failure!)
  end

  def http_ok(payload = {})
    response = Net::HTTPOK.new("1.1", "200", "OK")
    response.body = JSON.generate(payload)
    response["Content-Type"] = "application/json"
    response
  end

  it "sends the Google API key in a header rather than the query string" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    expect(provider).to receive(:request) do |uri, headers:, deadline:, **_options|
      query = URI.decode_www_form(uri.query.to_s)
      expect(query).to include(["uri", item.canonical])
      expect(query.map(&:first)).not_to include("key")
      expect(headers["X-Goog-Api-Key"]).to eq("test-key")
      expect(deadline).to be_a(Numeric)
      [http_ok, 20]
    end

    result = provider.check_many([item]).fetch(item.fingerprint)
    expect(result.status).to eq("clean")
  end

  it "does not count non-transient 4xx failures towards the circuit breaker" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    response = Net::HTTPForbidden.new("1.1", "403", "Forbidden")
    response.body = "{}"
    allow(provider).to receive(:request).and_return([response, 20])

    result = provider.check_many([item]).fetch(item.fingerprint)
    expect(result.error_code).to eq("http_403")
    expect(LinkSafety::CircuitBreaker).not_to have_received(:record_failure)
  end

  it "does count transient server failures towards the circuit breaker" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    response = Net::HTTPServiceUnavailable.new("1.1", "503", "Unavailable")
    response.body = "{}"
    allow(provider).to receive(:request).and_return([response, 20])

    provider.check_many([item])
    expect(LinkSafety::CircuitBreaker).to have_received(:record_failure).with("web_risk_lookup")
  end
  it "does not invent a negative-cache lifetime for an empty Lookup response" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    allow(provider).to receive(:request).and_return([http_ok, 20])

    result = provider.check_many([item]).fetch(item.fingerprint)
    expect(result.status).to eq("clean")
    expect(result.expires_at).to be <= Time.zone.now + 1.second
  end

  it "rejects a threat response without expireTime instead of inventing a local warning lifetime" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    allow(provider).to receive(:request).and_return(
      [http_ok("threat" => { "threatTypes" => ["MALWARE"] }), 20],
    )

    result = provider.check_many([item]).fetch(item.fingerprint)
    expect(result.status).to eq("error")
    expect(result.error_code).to eq("malformed_response")
  end

  it "rejects an expired threat response instead of enforcing stale data" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    allow(provider).to receive(:request).and_return(
      [http_ok("threat" => { "threatTypes" => ["MALWARE"], "expireTime" => 1.minute.ago.iso8601 }), 20],
    )

    result = provider.check_many([item]).fetch(item.fingerprint)
    expect(result.status).to eq("error")
    expect(result.error_code).to eq("stale_provider_response")
  end

  it "fails closed at the provider boundary on an unknown future threat type" do
    item = LinkSafety::Canonicalizer.call("https://example.com/")
    allow(provider).to receive(:request).and_return(
      [http_ok("threat" => { "threatTypes" => ["FUTURE_THREAT"], "expireTime" => 5.minutes.from_now.iso8601 }), 20],
    )

    result = provider.check_many([item]).fetch(item.fingerprint)
    expect(result.status).to eq("error")
    expect(result.error_code).to eq("unsupported_threat_type")
  end

end
