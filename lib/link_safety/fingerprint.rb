# frozen_string_literal: true

require "openssl"

module ::LinkSafety
  class Fingerprint
    PURPOSE = "discourse-link-safety-url-fingerprint-v1".freeze

    def self.for_url(value)
      OpenSSL::HMAC.hexdigest("SHA256", derived_key, value.to_s.b)
    end

    def self.for_unverified(value)
      for_url("unverified\0#{value}")
    end

    def self.derived_key
      secret = Rails.application.secret_key_base.to_s
      raise "missing Rails secret_key_base" if secret.empty?

      OpenSSL::HMAC.digest(
        "SHA256",
        secret,
        "#{PURPOSE}\0#{Discourse.current_hostname}",
      )
    end
    private_class_method :derived_key
  end
end
