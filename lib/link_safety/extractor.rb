# frozen_string_literal: true

module ::LinkSafety
  class Extractor
    def self.from_post_raw(raw, topic_id)
      return [] if raw.blank?
      ::PostAnalyzer.new(raw, topic_id).raw_links
    rescue => e
      Rails.logger.warn("[LinkSafety] post link extraction failed class=#{e.class.name}")
      []
    end

    def self.from_chat_message(message, user: nil)
      return [] if message.blank? || !defined?(::Chat::Message)
      cooked = ::Chat::Message.cook(
        message,
        user_id: user&.id,
        author_username: user&.username,
      )
      from_cooked(cooked)
    rescue => e
      Rails.logger.warn("[LinkSafety] chat link extraction failed class=#{e.class.name}")
      []
    end

    def self.from_cooked(cooked)
      return [] if cooked.blank?
      ::PrettyText.extract_links(cooked).map(&:url).compact
    rescue => e
      Rails.logger.warn("[LinkSafety] cooked link extraction failed class=#{e.class.name}")
      []
    end
  end
end
