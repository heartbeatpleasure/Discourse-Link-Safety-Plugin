# frozen_string_literal: true

require "digest"
require "ipaddr"
require "uri"

module ::LinkSafety
  class Canonicalizer
    CanonicalUrl = Data.define(:original, :canonical, :host, :fingerprint)

    def self.call(url)
      new(url).call
    end

    def initialize(url)
      @original = url.to_s
    end

    def call
      value = @original.delete("\t\r\n").strip
      return if value.empty?

      if value.start_with?("//")
        value = "http:#{value}"
      elsif !value.match?(%r{\Ahttps?://}i)
        value = "http://#{value}"
      end
      # Safe Browsing removes the literal fragment before percent-unescaping.
      value = value.split("#", 2).first

      uri = parse_url(value)
      return unless uri
      return unless %w[http https].include?(uri.scheme.to_s.downcase)
      return if uri.host.to_s.empty?

      scheme = uri.scheme.downcase
      host = canonical_host(repeatedly_unescape(uri.host.to_s))
      return if host.to_s.empty?

      raw_path = uri.path.to_s.empty? ? "/" : uri.path.to_s
      path = canonical_path(repeatedly_unescape(raw_path))
      query = uri.query.nil? ? nil : repeatedly_unescape(uri.query.to_s)

      canonical = "#{scheme}://#{safe_browsing_escape(host)}#{safe_browsing_escape(path)}"
      canonical += "?#{safe_browsing_escape(query)}" unless query.nil?

      CanonicalUrl.new(
        original: @original,
        canonical: canonical,
        host: safe_browsing_escape(host),
        fingerprint: Digest::SHA256.hexdigest(canonical),
      )
    rescue URI::Error, ArgumentError, EncodingError
      nil
    end

    def self.safe_browsing_expressions(canonical_url)
      uri = URI.parse(canonical_url)
      host = uri.host.to_s
      path = uri.path.to_s.empty? ? "/" : uri.path.to_s
      query = uri.query
      return [] if host.empty?

      hosts =
        if ip_address?(host)
          [host]
        else
          labels = host.split(".")
          list = [host]
          # Full hostname plus up to four suffixes. For long hosts, only suffixes
          # containing the last five components are considered.
          start = [labels.length - 5, 1].max
          (start..(labels.length - 2)).each { |idx| list << labels[idx..].join(".") } if labels.length > 1
          list.uniq.first(5)
        end

      paths = []
      paths << "#{path}?#{query}" unless query.nil?
      paths << path
      paths << "/"

      # Add at most four directory prefixes at actual slash boundaries. Do not
      # manufacture a trailing slash after a filename (e.g. /1/2.html/).
      slash_positions = []
      path.each_char.with_index { |ch, idx| slash_positions << idx if ch == "/" && idx.positive? }
      slash_positions.first(4).each { |idx| paths << path[0..idx] }

      hosts.product(paths.uniq.first(6)).map { |h, p| "#{h}#{p}" }.uniq
    rescue URI::Error, ArgumentError
      []
    end

    def self.ip_address?(host)
      IPAddr.new(host)
      true
    rescue IPAddr::InvalidAddressError
      false
    end

    private


    def parse_url(value)
      URI.parse(value)
    rescue URI::InvalidURIError
      # Discourse ships Addressable and uses it for Unicode/IDN URL normalization.
      begin
        Addressable::URI.parse(value)
      rescue StandardError
        nil
      end
    end

    def repeatedly_unescape(value)
      current = value.to_s
      16.times do
        decoded = URI::DEFAULT_PARSER.unescape(current)
        break if decoded == current
        current = decoded
      end
      current
    end

    def canonical_host(host)
      normalized = host.to_s.downcase.gsub(/\A\.+|\.+\z/, "").gsub(/\.{2,}/, ".")
      return if normalized.empty?

      if (ipv4 = normalize_ipv4(normalized))
        return ipv4
      end

      begin
        ip = IPAddr.new(normalized)
        return ip.to_s
      rescue IPAddr::InvalidAddressError
      end

      if !normalized.ascii_only?
        normalized = Addressable::IDNA.to_ascii(normalized).downcase
      end
      normalized
    rescue ArgumentError
      nil
    end

    # Safe Browsing requires support for legal IPv4 spellings such as a single
    # 32-bit integer, octal/hex components, and fewer than four components.
    def normalize_ipv4(host)
      parts = host.split(".", -1)
      return if parts.empty? || parts.length > 4 || parts.any?(&:empty?)
      return unless parts.all? { |part| part.match?(/\A(?:0[xX][0-9a-fA-F]+|0[0-7]*|[0-9]+)\z/) }

      values = parts.map { |part| parse_ipv4_number(part) }
      return if values.any?(&:nil?)

      value =
        case values.length
        when 1
          return if values[0] > 0xFFFF_FFFF
          values[0]
        when 2
          return if values[0] > 0xFF || values[1] > 0xFF_FFFF
          (values[0] << 24) | values[1]
        when 3
          return if values[0] > 0xFF || values[1] > 0xFF || values[2] > 0xFFFF
          (values[0] << 24) | (values[1] << 16) | values[2]
        when 4
          return if values.any? { |v| v > 0xFF }
          (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]
        end

      [24, 16, 8, 0].map { |shift| (value >> shift) & 0xFF }.join(".")
    rescue ArgumentError
      nil
    end

    def parse_ipv4_number(value)
      if value.match?(/\A0[xX]/)
        value.to_i(16)
      elsif value.length > 1 && value.start_with?("0")
        value.to_i(8)
      else
        value.to_i(10)
      end
    end

    def canonical_path(path)
      normalized = path.to_s.gsub(%r{/+}, "/")
      normalized = "/#{normalized}" unless normalized.start_with?("/")

      stack = []
      trailing_slash = normalized.end_with?("/")
      normalized.split("/").each do |segment|
        next if segment.empty? || segment == "."
        if segment == ".."
          stack.pop
        else
          stack << segment
        end
      end

      result = "/#{stack.join("/")}"
      result += "/" if trailing_slash && result != "/"
      result.empty? ? "/" : result
    end

    def safe_browsing_escape(value)
      value.to_s.b.bytes.map do |byte|
        if byte <= 32 || byte >= 127 || byte == 35 || byte == 37
          "%%%02X" % byte
        else
          byte.chr
        end
      end.join
    end
  end
end
