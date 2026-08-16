# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "timeout"

module ::LinkSafety
  module Providers
    class Base
      MAX_RESPONSE_BYTES = 512 * 1024
      USER_AGENT = "Discourse-Link-Safety-Plugin/1.1.0".freeze

      TRANSIENT_ERROR_CODES = %w[
        connect_timeout
        read_timeout
        dns_error
        tls_error
        network_error
        http_408
        http_425
        http_429
      ].freeze

      Response = Data.define(:status, :threat_types, :expires_at, :error_code, :latency_ms, :provider_calls)
      class ValidationDeadlineExceeded < StandardError; end

      def connect_timeout
        SiteSetting.link_safety_connect_timeout_ms.to_i / 1000.0
      end

      def read_timeout
        SiteSetting.link_safety_read_timeout_ms.to_i / 1000.0
      end

      def validation_deadline
        Process.clock_gettime(Process::CLOCK_MONOTONIC) +
          (SiteSetting.link_safety_validation_budget_ms.to_i / 1000.0)
      end

      def deadline_expired?(deadline)
        deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      end

      def request(uri, method: :get, headers: {}, body: nil, deadline: nil)
        remaining = remaining_budget(deadline)
        return [nil, nil, :validation_budget_exceeded] if remaining && remaining <= 0

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?
        http.open_timeout = bounded_timeout(connect_timeout, remaining)
        http.read_timeout = bounded_timeout(read_timeout, remaining)

        req = method == :post ? Net::HTTP::Post.new(uri.request_uri) : Net::HTTP::Get.new(uri.request_uri)
        req["User-Agent"] = USER_AGENT
        req["Accept"] = "application/json"
        headers.each { |k, v| req[k] = v }
        req.body = body if body

        response =
          if remaining
            Timeout.timeout(remaining, ValidationDeadlineExceeded) { http.request(req) }
          else
            http.request(req)
          end
        latency = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
        [response, latency]
      rescue ValidationDeadlineExceeded
        [nil, nil, :validation_budget_exceeded]
      rescue Net::OpenTimeout
        [nil, nil, :connect_timeout]
      rescue Net::ReadTimeout
        [nil, nil, :read_timeout]
      rescue SocketError
        [nil, nil, :dns_error]
      rescue OpenSSL::SSL::SSLError
        [nil, nil, :tls_error]
      rescue IOError, EOFError, SystemCallError => e
        Rails.logger.warn("[LinkSafety] provider network failure class=#{e.class.name}")
        [nil, nil, :network_error]
      rescue => e
        Rails.logger.warn("[LinkSafety] provider request failed internally class=#{e.class.name}")
        [nil, nil, :provider_internal_error]
      end

      def parse_json(response)
        body = response.body.to_s
        return if body.bytesize > MAX_RESPONSE_BYTES
        JSON.parse(body)
      rescue JSON::ParserError
        nil
      end

      def transient_failure?(error)
        value = error.to_s
        return true if TRANSIENT_ERROR_CODES.include?(value)
        return true if value.match?(/\Ahttp_5\d\d\z/)

        false
      end

      private

      def remaining_budget(deadline)
        return unless deadline
        deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def bounded_timeout(configured, remaining)
        return configured unless remaining
        [[configured, remaining].min, 0.001].max
      end
    end
  end
end
