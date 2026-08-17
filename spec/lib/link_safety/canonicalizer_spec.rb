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
      "http://host.com/ab%23c" => "http://host.com/ab%23c",
    }.each do |input, expected|
      it "canonicalizes #{input.inspect}" do
        expect(described_class.call(input)&.canonical).to eq(expected)
      end
    end

    it "distinguishes a literal fragment delimiter from an encoded hash in the path" do
      expect(described_class.call("http://host.com/ab%23c#fragment")&.canonical).to eq(
        "http://host.com/ab%23c",
      )
    end

    it "preserves an encoded hash inside the query as URL data" do
      expect(described_class.call("http://host.com/a?value=x%23y#fragment")&.canonical).to eq(
        "http://host.com/a?value=x%23y",
      )
    end

    it "removes tab, CR and LF characters" do
      input = "http://www.google.com/foo\tbar\rbaz\n2"
      expect(described_class.call(input)&.canonical).to eq("http://www.google.com/foobarbaz2")
    end

    it "handles a scheme-relative URL" do
      expect(described_class.call("//example.com/a")&.canonical).to eq("http://example.com/a")
    end

    it "keeps canonical IPv6 addresses bracketed" do
      item = described_class.call("http://[2001:0db8:0000:0000:0000:0000:0000:0001]/a")
      expect(item.canonical).to eq("http://[2001:db8::1]/a")
      expect(described_class.safe_browsing_expressions(item.canonical)).to include("[2001:db8::1]/a")
    end

    it "converts IPv4-mapped IPv6 addresses to IPv4" do
      expect(described_class.call("http://[::ffff:192.0.2.128]/")&.canonical).to eq("http://192.0.2.128/")
    end

    it "converts NAT64 well-known-prefix addresses to IPv4" do
      expect(described_class.call("http://[64:ff9b::192.0.2.128]/")&.canonical).to eq("http://192.0.2.128/")
    end

    it "returns a typed error instead of silently accepting excessive recursive percent encoding" do
      nested = "%2F"
      (described_class::MAX_UNESCAPE_PASSES + 1).times { nested = nested.gsub("%", "%25") }

      outcome = described_class.analyze("http://example.com/#{nested}")
      expect(outcome).to be_error
      expect(outcome.error_code).to eq("excessive_percent_encoding")
    end

    it "ignores explicit non-http schemes rather than rewriting them as HTTP" do
      outcome = described_class.analyze("mailto:test@example.com")
      expect(outcome).to be_ignored
      expect(outcome.error_code).to eq("unsupported_scheme")
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

    it "uses the registrable domain as the host-suffix boundary" do
      expressions = described_class.safe_browsing_expressions("http://x.a.b.c.example.co.uk/1.html")
      hosts = expressions.map { |expression| expression.split("/", 2).first }.uniq

      expect(hosts).to contain_exactly(
        "example.co.uk",
        "c.example.co.uk",
        "b.c.example.co.uk",
        "a.b.c.example.co.uk",
        "x.a.b.c.example.co.uk",
      )
      expect(hosts).not_to include("co.uk")
    end

    it "keeps the documented maximum of five host candidates" do
      expressions = described_class.safe_browsing_expressions("http://a.b.c.d.e.f.com/1.html")
      hosts = expressions.map { |expression| expression.split("/", 2).first }.uniq
      expect(hosts.length).to eq(5)
      expect(hosts).to include("f.com", "a.b.c.d.e.f.com")
    end

    it "keeps an encoded hash in the full Safe Browsing path expression" do
      item = described_class.call("http://host.com/ab%23c")
      expressions = described_class.safe_browsing_expressions(item.canonical)

      expect(expressions).to include("host.com/ab%23c")
      expect(expressions).not_to include("host.com/ab")
    end

    it "does not manufacture a filename path with a trailing slash" do
      expressions = described_class.safe_browsing_expressions("http://a.b.c/1/2.html")
      expect(expressions).not_to include("a.b.c/1/2.html/")
    end
  end
end
