# frozen_string_literal: true

require "digest"
require "ipaddr"
require "mini_suffix"
require "socket"
require "uri"

module ::LinkSafety
  class Canonicalizer
    MAX_URL_BYTES = 16 * 1024
    MAX_UNESCAPE_PASSES = 64
    NAT64_WELL_KNOWN_PREFIX = IPAddr.new("64:ff9b::/96")

    CanonicalUrl = Data.define(:original, :canonical, :host, :fingerprint, :legacy_fingerprint)
    Outcome = Data.define(:status, :item, :error_code) do
      def ok? = status.to_s == "ok"
      def ignored? = status.to_s == "ignored"
      def error? = status.to_s == "error"
    end

    class CanonicalizationError < StandardError
      attr_reader :code

      def initialize(code)
        @code = code.to_s
        super(@code)
      end
    end

    def self.call(url)
      analyze(url).item
    end

    def self.analyze(url)
      new(url).analyze
    end

    def initialize(url)
      @original = url.to_s
    end

    def analyze
      value = @original.delete("\t\r\n").strip
      return Outcome.new(status: "ignored", item: nil, error_code: "blank") if value.empty?
      raise CanonicalizationError, :url_too_long if value.bytesize > MAX_URL_BYTES

      explicit_scheme = value[/\A([a-z][a-z0-9+.-]*):/i, 1]&.downcase
      if !explicit_scheme.to_s.empty? && !%w[http https].include?(explicit_scheme)
        return Outcome.new(status: "ignored", item: nil, error_code: "unsupported_scheme")
      end

      if value.start_with?("//")
        value = "http:#{value}"
      elsif explicit_scheme.to_s.empty?
        value = "http://#{value}"
      end

      # Safe Browsing removes the literal fragment before percent-unescaping.
      # A # that appears only after recursive percent-decoding is therefore URL
      # data, not a fragment delimiter. Protect those decoded hashes while the
      # generic URI parser separates host/path/query, then restore them inside
      # the individual components before canonicalization.
      value = value.split("#", 2).first
      value = repeatedly_unescape(value)
      value = protect_decoded_hashes(value)

      uri = parse_url(value)
      raise CanonicalizationError, :invalid_url unless uri
      return Outcome.new(status: "ignored", item: nil, error_code: "unsupported_scheme") unless %w[http https].include?(uri.scheme.to_s.downcase)
      raise CanonicalizationError, :invalid_url if uri.host.to_s.empty?

      scheme = uri.scheme.downcase
      host = canonical_host(restore_decoded_hashes(uri.host.to_s))
      raise CanonicalizationError, :invalid_url if host.to_s.empty?

      raw_path = uri.path.to_s.empty? ? "/" : restore_decoded_hashes(uri.path.to_s)
      path = canonical_path(raw_path)
      query = uri.query.nil? ? nil : restore_decoded_hashes(uri.query.to_s)

      canonical = "#{scheme}://#{safe_browsing_escape(host)}#{safe_browsing_escape(path)}"
      canonical += "?#{safe_browsing_escape(query)}" unless query.nil?

      item = CanonicalUrl.new(
        original: @original,
        canonical: canonical,
        host: safe_browsing_escape(host),
        fingerprint: ::LinkSafety::Fingerprint.for_url(canonical),
        legacy_fingerprint: Digest::SHA256.hexdigest(canonical),
      )
      Outcome.new(status: "ok", item: item, error_code: nil)
    rescue CanonicalizationError => e
      Outcome.new(status: "error", item: nil, error_code: e.code)
    rescue URI::Error, ArgumentError, EncodingError
      Outcome.new(status: "error", item: nil, error_code: "invalid_url")
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] canonicalization failed class=#{e.class.name}") if defined?(Rails)
      ::LinkSafety::HealthRegistry.control_failure!(component: :canonicalizer, code: e.class.name) if defined?(::LinkSafety::HealthRegistry)
      Outcome.new(status: "error", item: nil, error_code: "canonicalization_failure")
    end

    def self.safe_browsing_expressions(canonical_url)
      safe_browsing_expressions!(canonical_url)
    rescue CanonicalizationError, URI::Error, ArgumentError
      []
    end

    def self.safe_browsing_expressions!(canonical_url)
      uri = URI.parse(canonical_url)
      host = uri.host.to_s
      path = uri.path.to_s.empty? ? "/" : uri.path.to_s
      query = uri.query
      raise CanonicalizationError, :canonicalization_failure if host.empty?

      hosts = host_candidates(host)
      raise CanonicalizationError, :canonicalization_failure if hosts.empty?

      paths = []
      paths << "#{path}?#{query}" unless query.nil?
      paths << path
      paths << "/"

      # Add at most four directory prefixes at actual slash boundaries. Do not
      # manufacture a trailing slash after a filename (e.g. /1/2.html/).
      slash_positions = []
      path.each_char.with_index { |ch, idx| slash_positions << idx if ch == "/" && idx.positive? }
      slash_positions.first(4).each { |idx| paths << path[0..idx] }

      expressions = hosts.product(paths.uniq.first(6)).map { |h, p| "#{h}#{p}" }.uniq
      raise CanonicalizationError, :canonicalization_failure if expressions.empty?
      expressions
    rescue URI::Error, ArgumentError => e
      raise CanonicalizationError, :canonicalization_failure, cause: e
    end

    def self.ip_address?(host)
      IPAddr.new(host)
      true
    rescue IPAddr::InvalidAddressError
      false
    end

    def self.host_candidates(host)
      return [host] if ip_address?(host)

      labels = host.split(".")
      return [host] if labels.length <= 1

      registrable = MiniSuffix.domain(host)
      registrable = nil if registrable.to_s.empty?
      registrable ||= labels.last(2).join(".")
      base_labels = registrable.split(".")
      base_start = labels.length - base_labels.length
      return [host] if base_start.negative?

      candidates = [registrable]
      current = registrable
      idx = base_start - 1
      while idx >= 0 && candidates.length < 4
        current = "#{labels[idx]}.#{current}"
        candidates << current
        idx -= 1
      end
      candidates << host
      candidates.uniq.first(5)
    rescue StandardError => e
      raise CanonicalizationError.new(:canonicalization_failure), cause: e
    end
    private_class_method :host_candidates

    private

    def parse_url(value)
      URI.parse(value)
    rescue URI::InvalidURIError
      begin
        Addressable::URI.parse(value)
      rescue StandardError
        nil
      end
    end

    def protect_decoded_hashes(value)
      value.to_s.gsub("#", "%23")
    end

    def restore_decoded_hashes(value)
      value.to_s.gsub(/%23/i, "#")
    end

    def repeatedly_unescape(value)
      current = value.to_s
      MAX_UNESCAPE_PASSES.times do
        decoded = URI::DEFAULT_PARSER.unescape(current)
        return current if decoded == current
        current = decoded
      end

      if current.match?(/%[0-9a-fA-F]{2}/)
        raise CanonicalizationError, :excessive_percent_encoding
      end
      current
    end

    def canonical_host(host)
      normalized = host.to_s.downcase.gsub(/\A\[|\]\z/, "")
      normalized = normalized.gsub(/\A\.+|\.+\z/, "").gsub(/\.{2,}/, ".")
      return if normalized.empty?

      if (ipv4 = normalize_ipv4(normalized))
        return ipv4
      end

      begin
        ip = IPAddr.new(normalized)
        return ip.native.to_s if ip.ipv4_mapped?
        if ip.ipv6? && NAT64_WELL_KNOWN_PREFIX.include?(ip)
          return IPAddr.new(ip.to_i & 0xFFFF_FFFF, Socket::AF_INET).to_s
        end
        return ip.ipv6? ? "[#{ip}]" : ip.to_s
      rescue IPAddr::InvalidAddressError
      end

      normalized = Addressable::IDNA.to_ascii(normalized).downcase unless normalized.ascii_only?
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
