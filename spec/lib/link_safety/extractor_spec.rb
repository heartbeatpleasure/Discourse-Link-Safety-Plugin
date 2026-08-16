# frozen_string_literal: true

RSpec.describe LinkSafety::Extractor do
  describe ".post_raw_result" do
    it "recovers a standalone onebox-candidate URL when PostAnalyzer raw_links omits it" do
      analyzer = instance_double(PostAnalyzer, raw_links: [])
      allow(PostAnalyzer).to receive(:new).with(
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/",
        nil,
      ).and_return(analyzer)

      result = described_class.post_raw_result(
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/",
        nil,
      )

      expect(result.error_code).to be_nil
      expect(result.urls).to eq(
        ["http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"],
      )
    end

    it "accepts surrounding whitespace around a standalone URL" do
      analyzer = instance_double(PostAnalyzer, raw_links: [])
      allow(PostAnalyzer).to receive(:new).and_return(analyzer)

      result = described_class.post_raw_result("  https://example.com/path  \n", 42)

      expect(result.urls).to eq(["https://example.com/path"])
    end

    it "does not turn arbitrary prose into a fallback URL" do
      analyzer = instance_double(PostAnalyzer, raw_links: [])
      allow(PostAnalyzer).to receive(:new).and_return(analyzer)

      result = described_class.post_raw_result("test https://example.com/", 42)

      expect(result.urls).to be_empty
    end

    it "does not duplicate a standalone URL already returned by PostAnalyzer" do
      url = "https://example.com/"
      analyzer = instance_double(PostAnalyzer, raw_links: [url])
      allow(PostAnalyzer).to receive(:new).and_return(analyzer)

      result = described_class.post_raw_result(url, 42)

      expect(result.urls).to eq([url])
    end
  end
end
