# frozen_string_literal: true

RSpec.describe LinkSafety::Providers::GoogleSafeBrowsingV5 do
  let(:provider) { described_class.new }

  describe "response helpers" do
    it "parses protobuf duration strings including zero" do
      expect(provider.send(:parse_duration, "0s")).to eq(0.0)
      expect(provider.send(:parse_duration, "3.5s")).to eq(3.5)
      expect(provider.send(:parse_duration, "3.123456789s")).to eq(3.123456789)
      expect(provider.send(:parse_duration, "invalid")).to be_nil
    end

    it "decodes padded and unpadded base64 bytes" do
      value = "\xBA\x78\x16\xBF".b
      padded = Base64.strict_encode64(value)
      unpadded = padded.delete("=")
      expect(provider.send(:decode_bytes, padded)).to eq(value)
      expect(provider.send(:decode_bytes, unpadded)).to eq(value)
    end
  end
end
