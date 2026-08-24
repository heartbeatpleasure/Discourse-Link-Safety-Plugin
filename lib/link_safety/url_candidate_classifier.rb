# frozen_string_literal: true

module ::LinkSafety
  # Classifies URLs as browser navigation candidates before Safe Browsing
  # canonicalization. Discourse cooking deliberately creates relative links for
  # mentions, hashtags, quotes, chat transcripts and other internal UI
  # constructs. Those references are not external websites and must never be
  # interpreted as malformed hostnames by the reputation checker.
  #
  # This class is intentionally conservative: only references that are
  # positively known to be internal/ignored are skipped. Malformed HTTP(S)
  # candidates continue to the Canonicalizer so Enforce mode can fail closed.
  class UrlCandidateClassifier
    HTTP_SCHEMES = %w[http https].freeze
    SCHEME_PATTERN = /\A([a-z][a-z0-9+.-]*):/i
    NETWORK_PATH_PATTERN = /\A[\\\/]{2,}/

    Classification = Data.define(:status, :url) do
      def checkable? = status.to_s == "checkable"
      def internal? = status.to_s == "internal"
      def ignored? = status.to_s == "ignored"
    end

    def self.classify(url)
      value = normalize_reference(url)
      return Classification.new(status: "ignored", url: nil) if value.empty?

      if network_path_reference?(value)
        candidate = normalize_network_path(value)
        return Classification.new(status: "internal", url: nil) if site_owned_resource?(candidate) || local_target?(candidate)

        return Classification.new(status: "checkable", url: candidate)
      end

      scheme = value[SCHEME_PATTERN, 1]&.downcase
      if scheme.present?
        return Classification.new(status: "ignored", url: nil) unless HTTP_SCHEMES.include?(scheme)

        if special_scheme_relative_reference?(value)
          # WHATWG treats special-scheme references without an authority prefix
          # as relative when their scheme matches the current document, e.g.
          # `https:next-page` on an HTTPS forum. With a different scheme the
          # same spelling becomes an absolute network target (`http:host`).
          if scheme == current_site_scheme
            return Classification.new(status: "internal", url: nil)
          end

          candidate = normalize_cross_scheme_reference(value, scheme)
        else
          candidate = normalize_http_network_separators(value)
        end

        return Classification.new(status: "internal", url: nil) if site_owned_resource?(candidate) || local_target?(candidate)

        return Classification.new(status: "checkable", url: candidate)
      end

      # Without an explicit HTTP(S) scheme or a network-path prefix the browser
      # resolves the value relative to the current Discourse origin. This covers
      # /t/..., /u/..., /groups/..., /c/..., /tag/..., /chat/..., fragments,
      # query-only links and future Discourse-generated relative routes without
      # hardcoding any route or hostname here.
      Classification.new(status: "internal", url: nil)
    rescue StandardError
      # A classifier failure must never silently whitelist something that looks
      # like an external HTTP(S) target. Preserve it for strict canonicalization.
      fallback = normalize_reference(url)
      if http_or_network_candidate?(fallback)
        Classification.new(status: "checkable", url: fallback)
      else
        Classification.new(status: "internal", url: nil)
      end
    end

    def self.filter(urls)
      Array(urls).compact.filter_map do |url|
        classification = classify(url)
        classification.url if classification.checkable?
      end.uniq
    end

    def self.normalize_reference(url)
      url.to_s.delete("\t\r\n").strip
    end
    private_class_method :normalize_reference

    def self.network_path_reference?(value)
      value.match?(NETWORK_PATH_PATTERN)
    end
    private_class_method :network_path_reference?

    # WHATWG special-scheme parsing treats backslashes like slashes for network
    # navigation. Normalize both the leading separator run and remaining
    # backslashes so classification/canonicalization sees the browser target.
    def self.normalize_network_path(value)
      network_path = value.sub(NETWORK_PATH_PATTERN, "//").tr("\\", "/")
      "#{current_site_scheme}:#{network_path}"
    end
    private_class_method :normalize_network_path

    def self.special_scheme_relative_reference?(value)
      remainder = value.sub(/\A[a-z][a-z0-9+.-]*:/i, "")
      !remainder.match?(/\A[\\\/]{2,}/)
    end
    private_class_method :special_scheme_relative_reference?

    def self.current_site_scheme
      scheme = SiteSetting.scheme.to_s.downcase
      HTTP_SCHEMES.include?(scheme) ? scheme : "https"
    end
    private_class_method :current_site_scheme

    def self.normalize_cross_scheme_reference(value, scheme)
      remainder = value.sub(/\A[a-z][a-z0-9+.-]*:/i, "")
      remainder = remainder.sub(/\A[\\\/]/, "")
      return value if remainder.blank? || remainder.start_with?("?", "#")

      "#{scheme}://#{remainder}".tr("\\", "/")
    end
    private_class_method :normalize_cross_scheme_reference

    def self.normalize_http_network_separators(value)
      match = value.match(/\A(https?):[\\\/]{2,}(.*)\z/i)
      candidate = match ? "#{match[1].downcase}://#{match[2]}" : value
      candidate.tr("\\", "/")
    end
    private_class_method :normalize_http_network_separators

    # Derive site-owned upload/CDN origins from the active FileStore at runtime.
    # Match both authority and path prefix ourselves instead of treating a
    # storage hostname as globally trusted; shared path-style object stores can
    # host unrelated buckets on the same hostname.
    def self.site_owned_resource?(value)
      candidate = parse_http_reference(value)
      return false unless candidate&.host.present?

      resource_base_urls.any? do |base_url|
        base = parse_http_reference(base_url)
        next false unless base&.host.present?
        next false unless same_authority?(candidate, base)

        path_within_base?(candidate.path, base.path)
      end
    rescue StandardError
      false
    end
    private_class_method :site_owned_resource?

    def self.resource_base_urls
      store = Discourse.store
      return [] unless store

      %i[absolute_base_url s3_upload_host absolute_base_cdn_url].filter_map do |method_name|
        next unless store.respond_to?(method_name)

        begin
          store.public_send(method_name).presence
        rescue StandardError
          nil
        end
      end.uniq
    rescue StandardError
      []
    end
    private_class_method :resource_base_urls

    def self.parse_http_reference(value)
      raw = value.to_s.strip
      raw = "#{current_site_scheme}:#{raw}" if raw.start_with?("//")
      uri = Addressable::URI.parse(raw)
      return unless HTTP_SCHEMES.include?(uri.scheme.to_s.downcase)

      uri
    rescue Addressable::URI::InvalidURIError, ArgumentError, TypeError
      nil
    end
    private_class_method :parse_http_reference

    def self.same_authority?(left, right)
      left.scheme.to_s.casecmp?(right.scheme.to_s) &&
        ::LinkSafety::TrustedDomains.normalize(left.host) == ::LinkSafety::TrustedDomains.normalize(right.host) &&
        effective_port(left) == effective_port(right)
    end
    private_class_method :same_authority?

    def self.effective_port(uri)
      uri.port || (uri.scheme.to_s.downcase == "https" ? 443 : 80)
    end
    private_class_method :effective_port

    def self.path_within_base?(candidate_path, base_path)
      candidate = browser_normalized_path(candidate_path)
      base = browser_normalized_path(base_path)
      return false if candidate.blank? || base.blank?
      return true if base == "/"

      prefix = base.end_with?("/") ? base : "#{base}/"
      candidate == base || candidate.start_with?(prefix)
    end
    private_class_method :path_within_base?

    # WHATWG special URLs treat backslashes as path separators and encoded dots
    # as dot-segments. Normalize those semantics before deciding that a URL is
    # inside a site-owned storage prefix, otherwise `/bucket/%2e%2e/other` could
    # be mistaken for a resource belonging to this site. Do not percent-decode
    # arbitrary characters such as `%2F`; browsers do not turn those into path
    # separators during URL parsing.
    def self.browser_normalized_path(path)
      raw = path.to_s.presence || "/"
      raw = raw.tr("\\", "/")
      trailing_slash = raw.end_with?("/")
      stack = []

      raw.split("/", -1).each do |segment|
        next if segment.empty?

        dot_form = segment.gsub(/%2e/i, ".")
        if dot_form == "."
          next
        elsif dot_form == ".."
          stack.pop
        else
          stack << segment
        end
      end

      normalized = "/#{stack.join("/")}"
      normalized += "/" if trailing_slash && normalized != "/"
      normalized
    rescue StandardError
      nil
    end
    private_class_method :browser_normalized_path

    def self.local_target?(value)
      parse_value = value.start_with?("//") ? "#{current_site_scheme}:#{value}" : value
      uri = Addressable::URI.parse(parse_value)
      host = uri.host.to_s
      return false if host.blank?

      ::LinkSafety::TrustedDomains.local_host?(host)
    rescue Addressable::URI::InvalidURIError, ArgumentError, TypeError
      false
    end
    private_class_method :local_target?

    def self.http_or_network_candidate?(value)
      return false if value.blank?
      return true if network_path_reference?(value)

      scheme = value[SCHEME_PATTERN, 1]&.downcase
      HTTP_SCHEMES.include?(scheme)
    end
    private_class_method :http_or_network_candidate?
  end
end
