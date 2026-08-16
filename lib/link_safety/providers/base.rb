# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"

module ::LinkSafety
  module Providers
    class Base
      MAX_RESPONSE_BYTES = 512 * 1024
      USER_AGENT = "Discourse-Link-Safety-Plugin/1.0.0".freeze

      Response = Data.define(:status, :threat_types, :expires_at, :error_code, :latency_ms, :provider_calls)

      def connect_timeout
        SiteSetting.link_safety_connect_timeout_ms.to_i / 1000.0
      end

      def read_timeout
        SiteSetting.link_safety_read_timeout_ms.to_i / 1000.0
      end

      def request(uri, method: :get, headers: {}, body: nil)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?
        http.open_timeout = connect_timeout
        http.read_timeout = read_timeout

        req = method == :post ? Net::HTTP::Post.new(uri.request_uri) : Net::HTTP::Get.new(uri.request_uri)
        req["User-Agent"] = USER_AGENT
        req["Accept"] = "application/json"
        headers.each { |k, v| req[k] = v }
        req.body = body if body

        response = http.request(req)
        latency = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
        [response, latency]
      rescue Net::OpenTimeout
        [nil, nil, :connect_timeout]
      rescue Net::ReadTimeout
        [nil, nil, :read_timeout]
      rescue SocketError
        [nil, nil, :dns_error]
      rescue OpenSSL::SSL::SSLError
        [nil, nil, :tls_error]
      rescue => e
        Rails.logger.warn("[LinkSafety] provider network failure class=#{e.class.name}")
        [nil, nil, :network_error]
      end

      def parse_json(response)
        body = response.body.to_s
        return if body.bytesize > MAX_RESPONSE_BYTES
        JSON.parse(body)
      rescue JSON::ParserError
        nil
      end
    end
  end
end
