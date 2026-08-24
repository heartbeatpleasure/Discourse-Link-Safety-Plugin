# frozen_string_literal: true

RSpec.describe LinkSafety::Checker do
  let(:item) { LinkSafety::Canonicalizer.call("https://example.com/path") }

  before do
    LinkSafety::CacheEntry.delete_all
    SiteSetting.link_safety_provider = "web_risk_lookup"
    SiteSetting.link_safety_trusted_domains = ""
    SiteSetting.link_safety_urlhaus_enabled = true
    SiteSetting.link_safety_urlhaus_auth_key = "test-key"
    SiteSetting.link_safety_urlhaus_private_surfaces = true
    SiteSetting.link_safety_web_risk_private_surfaces = true
    allow(LinkSafety::Statistics).to receive(:bump!)
    allow(LinkSafety::CircuitBreaker).to receive(:open?).and_return(false)
    allow(LinkSafety::LookupBudget).to receive(:reserve).and_return(
      LinkSafety::LookupBudget::Result.new(allowed: true, error_code: nil),
    )
  end

  it "keeps a URLhaus threat TTL independent from a zero-TTL clean Web Risk result" do
    primary = instance_double(LinkSafety::Providers::GoogleWebRisk)
    allow(primary).to receive(:validation_deadline).and_return(nil)
    allow(primary).to receive(:check_many).and_return(
      item.fingerprint => LinkSafety::Providers::Base::Response.new(
        status: "clean", threat_types: [], expires_at: Time.zone.now,
        error_code: nil, latency_ms: 10, provider_calls: 1,
      ),
    )
    allow_any_instance_of(described_class).to receive(:provider).and_return(primary)

    urlhaus = instance_double(LinkSafety::Providers::Urlhaus)
    allow(LinkSafety::Providers::Urlhaus).to receive(:new).and_return(urlhaus)
    allow(urlhaus).to receive(:check).and_return(
      LinkSafety::Providers::Base::Response.new(
        status: "threat", threat_types: ["MALWARE_DISTRIBUTION"], expires_at: 12.hours.from_now,
        error_code: nil, latency_ms: 10, provider_calls: 1,
      ),
    )

    result = described_class.check_many([item.original], surface: :public_post, force: true).first
    cache = LinkSafety::CacheEntry.lookup(
      provider: "web_risk_lookup", fingerprint: item.fingerprint,
      legacy_fingerprint: item.legacy_fingerprint,
    )

    expect(result.threat?).to eq(true)
    expect(result.provider).to eq("urlhaus")
    expect(cache).to be_present
    expect(cache.source_provider).to eq("urlhaus")
    expect(cache.expires_at).to be > 11.hours.from_now
  end

  it "retains a valid URLhaus threat when private URLhaus sharing is later disabled" do
    SiteSetting.link_safety_urlhaus_private_surfaces = false
    LinkSafety::CacheEntry.create!(
      provider: "web_risk_lookup",
      source_provider: "urlhaus",
      url_fingerprint: item.fingerprint,
      host: item.host,
      verdict: "threat",
      threat_types: ["MALWARE_DISTRIBUTION"],
      checked_at: 1.minute.ago,
      expires_at: 20.minutes.from_now,
    )

    primary = instance_double(LinkSafety::Providers::GoogleWebRisk)
    allow(primary).to receive(:validation_deadline).and_return(nil)
    allow(primary).to receive(:check_many).and_return(
      item.fingerprint => LinkSafety::Providers::Base::Response.new(
        status: "clean", threat_types: [], expires_at: Time.zone.now,
        error_code: nil, latency_ms: 10, provider_calls: 1,
      ),
    )
    allow_any_instance_of(described_class).to receive(:provider).and_return(primary)
    expect(LinkSafety::Providers::Urlhaus).not_to receive(:new)

    result = described_class.check_many(
      [item.original], surface: :public_post, private_content: true, force: true,
    ).first

    expect(result.threat?).to eq(true)
    expect(result.provider).to eq("urlhaus")
  end

  it "can bypass explicit trusted domains for an admin diagnostic" do
    SiteSetting.link_safety_trusted_domains = "example.com"
    SiteSetting.link_safety_urlhaus_enabled = false
    provider = instance_double(LinkSafety::Providers::GoogleWebRisk)
    allow(provider).to receive(:validation_deadline).and_return(nil)
    expect(provider).to receive(:check_many).and_return(
      item.fingerprint => LinkSafety::Providers::Base::Response.new(
        status: "clean", threat_types: [], expires_at: Time.zone.now,
        error_code: nil, latency_ms: 10, provider_calls: 1,
      ),
    )
    allow_any_instance_of(described_class).to receive(:provider).and_return(provider)

    described_class.check_many(
      [item.original], surface: :admin_test, force: true,
      bypass_trusted: true, bypass_lookup_budget: true, bypass_circuit: true,
    )
  end
  it "clears an older cached threat when zero-TTL Web Risk explicitly returns clean" do
    SiteSetting.link_safety_urlhaus_enabled = false
    LinkSafety::CacheEntry.create!(
      provider: "web_risk_lookup",
      source_provider: "web_risk_lookup",
      url_fingerprint: item.fingerprint,
      host: item.host,
      verdict: "threat",
      threat_types: ["MALWARE"],
      checked_at: 2.hours.ago,
      expires_at: 1.hour.ago,
    )

    primary = instance_double(LinkSafety::Providers::GoogleWebRisk)
    allow(primary).to receive(:validation_deadline).and_return(nil)
    allow(primary).to receive(:check_many).and_return(
      item.fingerprint => LinkSafety::Providers::Base::Response.new(
        status: "clean", threat_types: [], expires_at: Time.zone.now,
        error_code: nil, latency_ms: 10, provider_calls: 1,
      ),
    )
    allow_any_instance_of(described_class).to receive(:provider).and_return(primary)

    result = described_class.check_many([item.original], surface: :public_post, force: true).first

    expect(result.clean?).to eq(true)
    expect(
      LinkSafety::CacheEntry.lookup_any(
        provider: "web_risk_lookup", fingerprint: item.fingerprint,
        legacy_fingerprint: item.legacy_fingerprint,
      ),
    ).to be_nil
  end

  it "does not overwrite a still-valid threat when a forced refresh errors" do
    SiteSetting.link_safety_urlhaus_enabled = false
    LinkSafety::CacheEntry.create!(
      provider: "web_risk_lookup",
      source_provider: "web_risk_lookup",
      url_fingerprint: item.fingerprint,
      host: item.host,
      verdict: "threat",
      threat_types: ["MALWARE"],
      checked_at: 1.minute.ago,
      expires_at: 20.minutes.from_now,
    )

    primary = instance_double(LinkSafety::Providers::GoogleWebRisk)
    allow(primary).to receive(:validation_deadline).and_return(nil)
    allow(primary).to receive(:check_many).and_return(
      item.fingerprint => LinkSafety::Providers::Base::Response.new(
        status: "error", threat_types: [], expires_at: 1.minute.from_now,
        error_code: "read_timeout", latency_ms: nil, provider_calls: 0,
      ),
    )
    allow_any_instance_of(described_class).to receive(:provider).and_return(primary)

    result = described_class.check_many([item.original], surface: :public_post, force: true).first
    cache = LinkSafety::CacheEntry.lookup(
      provider: "web_risk_lookup", fingerprint: item.fingerprint,
      legacy_fingerprint: item.legacy_fingerprint,
    )

    expect(result.error?).to eq(true)
    expect(cache.verdict).to eq("threat")
    expect(cache.threat_types).to include("MALWARE")
  end

  it "does not overwrite an expired prior threat when a forced refresh errors" do
    SiteSetting.link_safety_urlhaus_enabled = false
    LinkSafety::CacheEntry.create!(
      provider: "web_risk_lookup",
      source_provider: "web_risk_lookup",
      url_fingerprint: item.fingerprint,
      host: item.host,
      verdict: "threat",
      threat_types: ["MALWARE"],
      checked_at: 2.hours.ago,
      expires_at: 1.minute.ago,
    )

    primary = instance_double(LinkSafety::Providers::GoogleWebRisk)
    allow(primary).to receive(:validation_deadline).and_return(nil)
    allow(primary).to receive(:check_many).and_return(
      item.fingerprint => LinkSafety::Providers::Base::Response.new(
        status: "error", threat_types: [], expires_at: 1.minute.from_now,
        error_code: "read_timeout", latency_ms: nil, provider_calls: 0,
      ),
    )
    allow_any_instance_of(described_class).to receive(:provider).and_return(primary)

    result = described_class.check_many([item.original], surface: :public_post, force: true).first
    historical = LinkSafety::CacheEntry.lookup_any(
      provider: "web_risk_lookup", fingerprint: item.fingerprint,
      legacy_fingerprint: item.legacy_fingerprint,
    )

    expect(result.error?).to eq(true)
    expect(historical.verdict).to eq("threat")
    expect(historical.expires_at).to be < Time.zone.now
  end

  it "keeps a prior supplemental threat when the primary turns clean but URLhaus refresh errors" do
    LinkSafety::CacheEntry.create!(
      provider: "web_risk_lookup",
      source_provider: "urlhaus",
      url_fingerprint: item.fingerprint,
      host: item.host,
      verdict: "threat",
      threat_types: ["MALWARE_DISTRIBUTION"],
      checked_at: 1.minute.ago,
      expires_at: 20.minutes.from_now,
    )

    primary = instance_double(LinkSafety::Providers::GoogleWebRisk)
    allow(primary).to receive(:validation_deadline).and_return(nil)
    allow(primary).to receive(:check_many).and_return(
      item.fingerprint => LinkSafety::Providers::Base::Response.new(
        status: "clean", threat_types: [], expires_at: Time.zone.now,
        error_code: nil, latency_ms: 10, provider_calls: 1,
      ),
    )
    allow_any_instance_of(described_class).to receive(:provider).and_return(primary)

    urlhaus = instance_double(LinkSafety::Providers::Urlhaus)
    allow(LinkSafety::Providers::Urlhaus).to receive(:new).and_return(urlhaus)
    allow(urlhaus).to receive(:check).and_return(
      LinkSafety::Providers::Base::Response.new(
        status: "error", threat_types: [], expires_at: 1.minute.from_now,
        error_code: "read_timeout", latency_ms: nil, provider_calls: 0,
      ),
    )

    result = described_class.check_many([item.original], surface: :public_post, force: true).first
    cache = LinkSafety::CacheEntry.lookup(
      provider: "web_risk_lookup", fingerprint: item.fingerprint,
      legacy_fingerprint: item.legacy_fingerprint,
    )

    expect(result.error?).to eq(true)
    expect(cache.verdict).to eq("threat")
    expect(cache.source_provider).to eq("urlhaus")
  end

end
