# frozen_string_literal: true

module ::LinkSafety
  class Extractor
    Extraction = Data.define(:urls, :error_code) do
      def success? = error_code.blank?
    end

    def self.post_raw_result(raw, topic_id)
      return Extraction.new(urls: [], error_code: nil) if raw.blank?
      Extraction.new(urls: Array(::PostAnalyzer.new(raw, topic_id).raw_links).compact, error_code: nil)
    rescue => e
      Rails.logger.warn("[LinkSafety] post link extraction failed class=#{e.class.name}")
      Extraction.new(urls: [], error_code: "extractor_failure")
    end

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
      Extraction.new(urls: [], error_code: "extractor_failure")
    end

    def self.markdown_result(raw)
      return Extraction.new(urls: [], error_code: nil) if raw.blank?
      cooked_result(::PrettyText.cook(raw))
    rescue => e
      Rails.logger.warn("[LinkSafety] markdown link extraction failed class=#{e.class.name}")
      Extraction.new(urls: [], error_code: "extractor_failure")
    end

    def self.cooked_result(cooked)
      return Extraction.new(urls: [], error_code: nil) if cooked.blank?
      urls = ::PrettyText.extract_links(cooked).map(&:url).compact
      Extraction.new(urls: urls, error_code: nil)
    rescue => e
      Rails.logger.warn("[LinkSafety] cooked link extraction failed class=#{e.class.name}")
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
