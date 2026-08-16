# frozen_string_literal: true

module ::LinkSafety
  Result = Data.define(
    :url,
    :canonical_url,
    :fingerprint,
    :host,
    :status,
    :threat_types,
    :provider,
    :checked_at,
    :expires_at,
    :error_code,
    :source,
  ) do
    def threat? = status.to_s == "threat"
    def clean? = status.to_s == "clean"
    def error? = status.to_s == "error"
    def trusted? = status.to_s == "trusted"
  end
end
