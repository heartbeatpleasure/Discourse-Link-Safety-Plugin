# frozen_string_literal: true

RSpec.describe LinkSafety::Canonicalizer do
  describe ".call" do
    {
      "http://host/%25%32%35" => "http://host/%25",
      "http://host/%25%32%35%25%32%35" => "http://host/%25%25",
      "http://host/%2525252525252525" => "http://host/%25",
      "http://host/asdf%25%32%35asd" => "http://host/asdf%25asd",
      "http://www.google.com/" => "http://www.google.com/",
      "http://3279880203/blah" => "http://195.127.0.11/blah",
      "http://www.google.com/blah/.." => "http://www.google.com/",
      "www.google.com/" => "http://www.google.com/",
      "www.google.com" => "http://www.google.com/",
      "http://www.evil.com/blah#frag" => "http://www.evil.com/blah",
      "http://www.GOOgle.com/" => "http://www.google.com/",
      "http://www.google.com.../" => "http://www.google.com/",
      "http://www.google.com/q?" => "http://www.google.com/q?",
      "http://www.google.com/q?r?" => "http://www.google.com/q?r?",
      "http://www.google.com/q?r?s" => "http://www.google.com/q?r?s",
      "http://evil.com/foo#bar#baz" => "http://evil.com/foo",
      "http://notrailingslash.com" => "http://notrailingslash.com/",
      "http://www.gotaport.com:1234/" => "http://www.gotaport.com/",
      "https://www.securesite.com/" => "https://www.securesite.com/",
      "http://host.com//twoslashes?more//slashes" => "http://host.com/twoslashes?more//slashes",
    }.each do |input, expected|
      it "canonicalizes #{input.inspect}" do
        expect(described_class.call(input)&.canonical).to eq(expected)
      end
    end

    it "removes tab, CR and LF characters" do
      input = "http://www.google.com/foo\tbar\rbaz\n2"
      expect(described_class.call(input)&.canonical).to eq("http://www.google.com/foobarbaz2")
    end

    it "handles a scheme-relative URL" do
      expect(described_class.call("//example.com/a")&.canonical).to eq("http://example.com/a")
    end
  end

  describe ".safe_browsing_expressions" do
    it "matches the documented a.b.c path/query expression set" do
      expressions = described_class.safe_browsing_expressions("http://a.b.c/1/2.html?param=1")
      expect(expressions).to contain_exactly(
        "a.b.c/1/2.html?param=1",
        "a.b.c/1/2.html",
        "a.b.c/",
        "a.b.c/1/",
        "b.c/1/2.html?param=1",
        "b.c/1/2.html",
        "b.c/",
        "b.c/1/",
      )
    end

    it "uses only the full host plus suffixes based on the last five host components" do
      expressions = described_class.safe_browsing_expressions("http://a.b.c.d.e.f.g/1.html")
      expect(expressions).to contain_exactly(
        "a.b.c.d.e.f.g/1.html",
        "a.b.c.d.e.f.g/",
        "c.d.e.f.g/1.html",
        "c.d.e.f.g/",
        "d.e.f.g/1.html",
        "d.e.f.g/",
        "e.f.g/1.html",
        "e.f.g/",
        "f.g/1.html",
        "f.g/",
      )
    end

    it "does not manufacture a filename path with a trailing slash" do
      expressions = described_class.safe_browsing_expressions("http://a.b.c/1/2.html")
      expect(expressions).not_to include("a.b.c/1/2.html/")
    end
  end
end
