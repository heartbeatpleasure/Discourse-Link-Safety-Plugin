# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "timeout"

module ::LinkSafety
  module Providers
    class Base
      MAX_RESPONSE_BYTES = 512 * 1024
      USER_AGENT = "Discourse-Link-Safety-Plugin/1.2.2".freeze

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
      class ResponseTooLarge < StandardError; end

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
        if http.use_ssl?
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          if http.respond_to?(:min_version=) && defined?(OpenSSL::SSL::TLS1_2_VERSION)
            http.min_version = OpenSSL::SSL::TLS1_2_VERSION
          end
        end
        http.open_timeout = bounded_timeout(connect_timeout, remaining)
        http.read_timeout = bounded_timeout(read_timeout, remaining)
        http.write_timeout = bounded_timeout(read_timeout, remaining) if http.respond_to?(:write_timeout=)

        req = method == :post ? Net::HTTP::Post.new(uri.request_uri) : Net::HTTP::Get.new(uri.request_uri)
        req["User-Agent"] = USER_AGENT
        req["Accept"] = "application/json"
        # Avoid transparent compression so the enforced byte ceiling reflects the
        # actual provider payload retained in memory.
        req["Accept-Encoding"] = "identity"
        headers.each { |k, v| req[k] = v }
        req.body = body if body

        response = nil
        perform = lambda do
          http.request(req) do |res|
            response = res
            enforce_content_length!(res)
            buffer = +"".b
            res.read_body do |chunk|
              raise ResponseTooLarge if buffer.bytesize + chunk.bytesize > MAX_RESPONSE_BYTES
              buffer << chunk
            end
            res.body = buffer
          end
        end

        if remaining
          Timeout.timeout(remaining, ValidationDeadlineExceeded) { perform.call }
        else
          perform.call
        end

        latency = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
        [response, latency]
      rescue ResponseTooLarge
        [nil, nil, :response_too_large]
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
        ::LinkSafety::HealthRegistry.control_failure!(component: :provider_request, code: e.class.name)
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

      def enforce_content_length!(response)
        raw = response["Content-Length"].to_s
        return if raw.empty?

        length = Integer(raw, exception: false)
        raise ResponseTooLarge if length && length > MAX_RESPONSE_BYTES
      end

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
