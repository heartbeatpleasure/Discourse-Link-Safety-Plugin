# frozen_string_literal: true

module ::LinkSafety
  # Implicit trust is intentionally origin-scoped, not hostname-scoped. A
  # different scheme or port on the same hostname can be an entirely different
  # service and must still pass reputation checking unless explicitly trusted.
  class SiteOrigin
    HTTP_SCHEMES = %w[http https].freeze

    def self.same?(url)
      candidate = parse(url)
      return false unless candidate

      origins.any? { |origin| same_origin?(candidate, origin) }
    rescue StandardError
      false
    end

    def self.origins
      parsed = [::Discourse.base_url, ::Discourse.base_url_no_prefix].filter_map { |value| parse(value) }
      parsed = parsed.uniq { |uri| origin_key(uri) }
      return parsed if parsed.any?

      # Fallback only if Discourse's canonical base URLs cannot be parsed. Do
      # not add current_hostname alongside a valid non-default-port base URL,
      # because that would silently trust the same host on port 80/443 too.
      if ::Discourse.respond_to?(:current_hostname) && ::Discourse.current_hostname.present?
        fallback = parse("#{current_scheme}://#{::Discourse.current_hostname}")
        return [fallback].compact
      end

      []
    rescue StandardError
      []
    end

    def self.parse(value)
      raw = value.to_s.strip
      return if raw.blank?
      raw = "#{current_scheme}:#{raw}" if raw.start_with?("//")
      uri = Addressable::URI.parse(raw)
      return unless HTTP_SCHEMES.include?(uri.scheme.to_s.downcase)
      return if uri.host.to_s.blank?

      uri
    rescue Addressable::URI::InvalidURIError, ArgumentError, TypeError
      nil
    end
    private_class_method :parse

    def self.same_origin?(left, right)
      origin_key(left) == origin_key(right)
    end
    private_class_method :same_origin?

    def self.origin_key(uri)
      [
        uri.scheme.to_s.downcase,
        ::LinkSafety::TrustedDomains.normalize(uri.host),
        effective_port(uri),
      ]
    end
    private_class_method :origin_key

    def self.effective_port(uri)
      uri.port || (uri.scheme.to_s.downcase == "https" ? 443 : 80)
    end
    private_class_method :effective_port

    def self.current_scheme
      scheme = SiteSetting.scheme.to_s.downcase
      HTTP_SCHEMES.include?(scheme) ? scheme : "https"
    end
    private_class_method :current_scheme
  end
end
