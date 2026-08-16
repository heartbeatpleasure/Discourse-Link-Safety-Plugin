# frozen_string_literal: true

RSpec.describe LinkSafety::Providers::GoogleSafeBrowsingV5 do
  let(:provider) { described_class.new }

  def protobuf_varint(value)
    bytes = []
    loop do
      byte = value & 0x7f
      value >>= 7
      byte |= 0x80 unless value.zero?
      bytes << byte
      break if value.zero?
    end
    bytes.pack("C*")
  end

  def protobuf_varint_field(field_number, value)
    protobuf_varint(field_number << 3) + protobuf_varint(value)
  end

  def protobuf_bytes_field(field_number, value)
    value = value.to_s.b
    protobuf_varint((field_number << 3) | 2) + protobuf_varint(value.bytesize) + value
  end

  def protobuf_duration(seconds, nanos = 0)
    body = protobuf_varint_field(1, seconds)
    body += protobuf_varint_field(2, nanos) unless nanos.zero?
    body
  end

  def protobuf_detail(threat_type:, attributes: [])
    body = protobuf_varint_field(1, threat_type)
    if attributes.any?
      packed = attributes.map { |attribute| protobuf_varint(attribute) }.join
      body += protobuf_bytes_field(2, packed)
    end
    body
  end

  def protobuf_full_hash(hash:, details: [])
    body = protobuf_bytes_field(1, hash)
    details.each { |detail| body += protobuf_bytes_field(2, detail) }
    body
  end

  def protobuf_response(full_hashes: [], cache_seconds: 300, cache_nanos: 0)
    body = +"".b
    full_hashes.each { |full_hash| body += protobuf_bytes_field(1, full_hash) }
    body += protobuf_bytes_field(2, protobuf_duration(cache_seconds, cache_nanos))
    body
  end

  describe "response helpers" do
    it "parses documented JSON duration strings including zero" do
      expect(provider.send(:parse_duration, "0s")).to eq(0.0)
      expect(provider.send(:parse_duration, "3.5s")).to eq(3.5)
      expect(provider.send(:parse_duration, "3.123456789s")).to eq(3.123456789)
      expect(provider.send(:parse_duration, "invalid")).to be_nil
    end

    it "decodes padded and unpadded base64 bytes for JSON compatibility" do
      value = "\xBA\x78\x16\xBF".b
      padded = Base64.strict_encode64(value)
      unpadded = padded.delete("=")
      expect(provider.send(:decode_bytes, padded)).to eq(value)
      expect(provider.send(:decode_bytes, unpadded)).to eq(value)
    end

    it "builds a v5 hashes search request without API-key or output-format query parameters" do
      prefix = "\xBA\x78\x16\xBF".b
      uri = provider.send(:build_search_uri, [prefix])
      decoded = URI.decode_www_form(uri.query)

      expect(decoded).to include(["hashPrefixes", Base64.strict_encode64(prefix)])
      expect(decoded.map(&:first)).not_to include("key", "alt", "$alt")
    end

    it "decodes the observed clean protobuf response and its 300 second cache duration" do
      # Wire bytes: SearchHashesResponse.cache_duration = Duration(seconds: 300)
      body = "\x12\x03\x08\xAC\x02".b
      payload = provider.send(:parse_protobuf_payload, body)

      expect(payload.full_hashes).to eq([])
      expect(payload.cache_duration).to eq(300.0)
    end

    it "decodes an enforceable malware full-hash match" do
      full_hash = Digest::SHA256.digest("example.com/")
      body = protobuf_response(
        full_hashes: [
          protobuf_full_hash(
            hash: full_hash,
            details: [protobuf_detail(threat_type: 1)],
          ),
        ],
        cache_seconds: 300,
      )

      payload = provider.send(:parse_protobuf_payload, body)
      entry = payload.full_hashes.first

      expect(entry[:full_hash]).to eq(full_hash)
      expect(entry[:details]).to eq([{ threat_type: 1, attributes: [] }])
      expect(provider.send(:enforceable_threat_names, entry[:details])).to eq(["MALWARE"])
      expect(payload.cache_duration).to eq(300.0)
    end

    it "disregards a detail carrying the CANARY attribute" do
      full_hash = Digest::SHA256.digest("example.com/")
      body = protobuf_response(
        full_hashes: [
          protobuf_full_hash(
            hash: full_hash,
            details: [protobuf_detail(threat_type: 1, attributes: [1])],
          ),
        ],
      )

      payload = provider.send(:parse_protobuf_payload, body)
      details = payload.full_hashes.first[:details]
      expect(details).to eq([{ threat_type: 1, attributes: [1] }])
      expect(provider.send(:enforceable_threat_names, details)).to be_empty
    end

    it "disregards a detail with a future unknown threat attribute" do
      full_hash = Digest::SHA256.digest("example.com/")
      body = protobuf_response(
        full_hashes: [
          protobuf_full_hash(
            hash: full_hash,
            details: [protobuf_detail(threat_type: 1, attributes: [99])],
          ),
        ],
      )

      payload = provider.send(:parse_protobuf_payload, body)
      expect(payload.full_hashes.first[:details]).to be_empty
    end

    it "disregards a detail with a future unknown threat type" do
      full_hash = Digest::SHA256.digest("example.com/")
      body = protobuf_response(
        full_hashes: [
          protobuf_full_hash(
            hash: full_hash,
            details: [protobuf_detail(threat_type: 99)],
          ),
        ],
      )

      payload = provider.send(:parse_protobuf_payload, body)
      expect(payload.full_hashes.first[:details]).to be_empty
    end

    it "supports nanoseconds in protobuf cache durations" do
      body = protobuf_response(cache_seconds: 3, cache_nanos: 500_000_000)
      payload = provider.send(:parse_protobuf_payload, body)
      expect(payload.cache_duration).to eq(3.5)
    end

    it "rejects a truncated protobuf response" do
      expect {
        provider.send(:parse_protobuf_payload, "\x12\x03\x08".b)
      }.to raise_error(described_class::ProtobufDecodeError)
    end
  end

  describe "protobuf provider integration" do
    before do
      SiteSetting.link_safety_google_api_key = "test-key"
      SiteSetting.link_safety_safe_browsing_noncommercial_acknowledged = true
      SiteSetting.link_safety_google_user_protection_notice_acknowledged = true
      allow(LinkSafety::Statistics).to receive(:bump!)
      allow(LinkSafety::CircuitBreaker).to receive(:record_success)
      allow(LinkSafety::CircuitBreaker).to receive(:record_failure)
      allow(LinkSafety::HealthRegistry).to receive(:success!)
      allow(LinkSafety::HealthRegistry).to receive(:failure!)
    end

    def http_ok(body, content_type: "application/x-protobuf")
      response = Net::HTTPOK.new("1.1", "200", "OK")
      response.body = body
      response["Content-Type"] = content_type
      response
    end


    it "sends the API key in X-Goog-Api-Key and applies the validation deadline" do
      item = LinkSafety::Canonicalizer.call("https://example.com/")
      expect(provider).to receive(:request) do |uri, headers:, deadline:, **_options|
        expect(URI.decode_www_form(uri.query.to_s).map(&:first)).not_to include("key")
        expect(headers["X-Goog-Api-Key"]).to eq("test-key")
        expect(headers["Accept"]).to eq("application/x-protobuf")
        expect(deadline).to be_a(Numeric)
        [http_ok("\x12\x03\x08\xAC\x02".b), 20]
      end

      expect(provider.check_many([item]).fetch(item.fingerprint).status).to eq("clean")
    end

    it "does not count non-transient 4xx failures towards the circuit breaker" do
      item = LinkSafety::Canonicalizer.call("https://example.com/")
      response = Net::HTTPForbidden.new("1.1", "403", "Forbidden")
      response.body = "{}"
      allow(provider).to receive(:request).and_return([response, 20])

      expect(provider.check_many([item]).fetch(item.fingerprint).error_code).to eq("http_403")
      expect(LinkSafety::CircuitBreaker).not_to have_received(:record_failure)
    end

    it "classifies the observed empty protobuf response as clean" do
      item = LinkSafety::Canonicalizer.call("https://example.com/")
      allow(provider).to receive(:request).and_return(
        [http_ok("\x12\x03\x08\xAC\x02".b), 20],
      )

      result = provider.check_many([item]).fetch(item.fingerprint)

      expect(result.status).to eq("clean")
      expect(result.threat_types).to eq([])
      expect(result.error_code).to be_nil
      expect(result.expires_at).to be_within(2.seconds).of(300.seconds.from_now)
    end

    it "caps anomalously long clean cache durations to 24 hours" do
      item = LinkSafety::Canonicalizer.call("https://example.com/")
      body = protobuf_response(cache_seconds: 7.days.to_i)
      allow(provider).to receive(:request).and_return([http_ok(body), 20])

      result = provider.check_many([item]).fetch(item.fingerprint)

      expect(result.status).to eq("clean")
      expect(result.expires_at).to be <= 24.hours.from_now + 2.seconds
    end

    it "classifies a matching malware full hash as a threat" do
      item = LinkSafety::Canonicalizer.call("https://example.com/")
      expression = LinkSafety::Canonicalizer.safe_browsing_expressions(item.canonical).first
      matching_hash = Digest::SHA256.digest(expression)
      body = protobuf_response(
        full_hashes: [
          protobuf_full_hash(
            hash: matching_hash,
            details: [protobuf_detail(threat_type: 1)],
          ),
        ],
      )
      allow(provider).to receive(:request).and_return([http_ok(body), 20])

      result = provider.check_many([item]).fetch(item.fingerprint)

      expect(result.status).to eq("threat")
      expect(result.threat_types).to eq(["MALWARE"])
      expect(result.error_code).to be_nil
      expect(result.expires_at).to be <= 30.minutes.from_now
    end

    it "does not enforce a matching CANARY detail" do
      item = LinkSafety::Canonicalizer.call("https://example.com/")
      expression = LinkSafety::Canonicalizer.safe_browsing_expressions(item.canonical).first
      matching_hash = Digest::SHA256.digest(expression)
      body = protobuf_response(
        full_hashes: [
          protobuf_full_hash(
            hash: matching_hash,
            details: [protobuf_detail(threat_type: 1, attributes: [1])],
          ),
        ],
      )
      allow(provider).to receive(:request).and_return([http_ok(body), 20])

      result = provider.check_many([item]).fetch(item.fingerprint)

      expect(result.status).to eq("clean")
      expect(result.threat_types).to eq([])
    end
  end

end
