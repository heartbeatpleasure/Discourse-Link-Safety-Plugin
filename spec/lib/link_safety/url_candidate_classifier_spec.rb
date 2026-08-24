# frozen_string_literal: true

RSpec.describe LinkSafety::UrlCandidateClassifier do
  let(:store) { double("store") }

  before do
    allow(SiteSetting).to receive(:scheme).and_return("https")
    allow(Discourse).to receive(:store).and_return(store)
    allow(LinkSafety::TrustedDomains).to receive(:local_host?).and_return(false)
  end

  it "treats browser-relative Discourse navigation as internal without route-specific rules" do
    [
      "/t/topic/123",
      "/u/example",
      "/groups/example",
      "/c/example/1",
      "/tag/example",
      "/chat/c/-/1",
      "./relative",
      "../relative",
      "?page=2",
      "#heading",
      "relative/path",
    ].each do |url|
      classification = described_class.classify(url)
      expect(classification).to be_internal, url
      expect(classification.url).to be_nil
    end
  end

  it "ignores non-HTTP navigation schemes" do
    %w[mailto:test@example.com tel:+31123456789 upload://abc123].each do |url|
      expect(described_class.classify(url)).to be_ignored, url
    end
  end

  it "keeps external HTTP and HTTPS targets checkable" do
    expect(described_class.classify("https://external.example/path")).to be_checkable
    expect(described_class.classify("http://external.example/path")).to be_checkable
  end

  it "follows browser semantics for special-scheme references without an authority prefix" do
    expect(described_class.classify("https:next-page")).to be_internal
    expect(described_class.classify("https:/next-page")).to be_internal
    expect(described_class.classify("https:\\next-page")).to be_internal

    expect(described_class.classify("http:external.example/path").url).to eq("http://external.example/path")
    expect(described_class.classify("http:/external.example/path").url).to eq("http://external.example/path")
    expect(described_class.classify("http:\\external.example/path").url).to eq("http://external.example/path")
  end

  it "normalizes protocol-relative and backslash network paths before checking" do
    expect(described_class.classify("//external.example/path").url).to eq("https://external.example/path")
    expect(described_class.classify("///external.example/path").url).to eq("https://external.example/path")
    expect(described_class.classify("/\\external.example/path").url).to eq("https://external.example/path")
    expect(described_class.classify("\\\\external.example\\path").url).to eq("https://external.example/path")
    expect(described_class.classify("https:\\\\external.example/path").url).to eq("https://external.example/path")
  end

  it "normalizes backslashes before deciding whether an HTTP target is local" do
    allow(LinkSafety::TrustedDomains).to receive(:local_host?) do |host|
      host == "forum.example"
    end

    external = described_class.classify("https://evil.example\\@forum.example/path")
    local = described_class.classify("https://forum.example\\@evil.example/path")

    expect(external).to be_checkable
    expect(external.url).to eq("https://evil.example/@forum.example/path")
    expect(local).to be_internal
  end

  it "skips an absolute URL on the current Discourse origin" do
    allow(LinkSafety::TrustedDomains).to receive(:local_host?) do |host|
      host == "forum.example"
    end

    classification = described_class.classify("https://forum.example/t/topic/1")
    expect(classification).to be_internal
  end

  it "uses the active FileStore origin and path to skip only resources owned by this site" do
    allow(store).to receive(:absolute_base_url).and_return("https://storage.example/this-site")

    owned = described_class.classify("https://storage.example/this-site/original/file.png")
    unrelated = described_class.classify("https://storage.example/other-tenant/file.png")
    deceptive = described_class.classify("https://evil.example/storage.example/this-site/file.png")

    expect(owned).to be_internal
    expect(unrelated).to be_checkable
    expect(deceptive).to be_checkable
  end

  it "does not let browser dot-segment normalization escape a site-owned storage path" do
    allow(store).to receive(:absolute_base_url).and_return("https://storage.example/this-site")

    [
      "https://storage.example/this-site/../other-tenant/file.png",
      "https://storage.example/this-site/%2e%2e/other-tenant/file.png",
      "https://storage.example/this-site/.%2e/other-tenant/file.png",
      "https://storage.example/this-site\\..\\other-tenant\\file.png",
    ].each do |url|
      expect(described_class.classify(url)).to be_checkable, url
    end
  end

  it "does not trust a different port on a site-owned storage hostname" do
    allow(store).to receive(:absolute_base_url).and_return("https://storage.example/this-site")

    classification = described_class.classify("https://storage.example:8443/this-site/file.png")
    expect(classification).to be_checkable
  end

  it "does not silently whitelist malformed explicit HTTP candidates" do
    classification = described_class.classify("https://")
    expect(classification).to be_checkable
    expect(classification.url).to eq("https://")
  end
end
