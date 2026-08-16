# frozen_string_literal: true

module ::LinkSafety
  class Extractor
    Extraction = Data.define(:urls, :error_code) do
      def success? = error_code.blank?
    end

    def self.post_raw_result(raw, topic_id)
      return Extraction.new(urls: [], error_code: nil) if raw.blank?

      urls = Array(::PostAnalyzer.new(raw, topic_id).raw_links).compact

      # Discourse treats a bare URL-only post as a onebox candidate. Depending
      # on the cooking path, PostAnalyzer#raw_links may omit that standalone
      # target even though it later becomes an <a class="onebox"> in cooked
      # content. Link Safety must validate it before persistence just like any
      # other external URL, otherwise Enforce can only neutralize it after the
      # post has already been saved. Keep this fallback deliberately narrow so
      # code blocks and ordinary prose are still governed by PostAnalyzer.
      standalone = standalone_http_url(raw)
      urls << standalone if standalone.present? && !urls.include?(standalone)

      Extraction.new(urls: urls.uniq, error_code: nil)
    rescue => e
      Rails.logger.warn("[LinkSafety] post link extraction failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :extractor, code: e.class.name)
      Extraction.new(urls: [], error_code: "extractor_failure")
    end

    def self.standalone_http_url(raw)
      candidate = raw.to_s.strip
      return if candidate.blank? || candidate.match?(/\s/)
      return unless candidate.match?(/\Ahttps?:\/\//i)

      candidate
    end
    private_class_method :standalone_http_url

    def self.chat_message_result(message, user: nil)
      return Extraction.new(urls: [], error_code: nil) if message.blank? || !defined?(::Chat::Message)
      cooked = ::Chat::Message.cook(
        message,
        user_id: user&.id,
        author_username: user&.username,
      )
      cooked_result(cooked)
    rescue => e
      Rails.logger.warn("[LinkSafety] chat link extraction failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :extractor, code: e.class.name)
      Extraction.new(urls: [], error_code: "extractor_failure")
    end

    def self.markdown_result(raw)
      return Extraction.new(urls: [], error_code: nil) if raw.blank?
      cooked_result(::PrettyText.cook(raw))
    rescue => e
      Rails.logger.warn("[LinkSafety] markdown link extraction failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :extractor, code: e.class.name)
      Extraction.new(urls: [], error_code: "extractor_failure")
    end

    def self.cooked_result(cooked)
      return Extraction.new(urls: [], error_code: nil) if cooked.blank?
      urls = ::PrettyText.extract_links(cooked).map(&:url).compact
      Extraction.new(urls: urls, error_code: nil)
    rescue => e
      Rails.logger.warn("[LinkSafety] cooked link extraction failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :extractor, code: e.class.name)
      Extraction.new(urls: [], error_code: "extractor_failure")
    end

    # Backwards-compatible array helpers for non-validation callers such as
    # pending scheduling. Security-sensitive validation uses the result methods
    # above so extraction failures cannot silently become an empty URL list.
    def self.from_post_raw(raw, topic_id)
      post_raw_result(raw, topic_id).urls
    end

    def self.from_chat_message(message, user: nil)
      chat_message_result(message, user: user).urls
    end

    def self.from_cooked(cooked)
      cooked_result(cooked).urls
    end
  end
end
