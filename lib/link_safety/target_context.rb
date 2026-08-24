# frozen_string_literal: true

module ::LinkSafety
  class TargetContext
    Context = Data.define(:surface, :actor, :private_content, :extraction)

    def self.for(target, actor_id: nil, expected_hash: nil, expected_version: nil, extract: true)
      case target
      when ::Post
        post_context(
          target,
          actor_id: actor_id,
          expected_hash: expected_hash,
          expected_version: expected_version,
          extract: extract,
        )
      when ::UserProfile
        profile_context(target, extract: extract)
      when ::Topic
        topic_context(target, extract: extract)
      when ::Group
        group_context(target, extract: extract)
      else
        if defined?(::Chat::Message) && target.is_a?(::Chat::Message)
          chat_context(
            target,
            actor_id: actor_id,
            expected_hash: expected_hash,
            expected_version: expected_version,
            extract: extract,
          )
        end
      end
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] target context failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :target_context, code: e.class.name)
      nil
    end

    def self.post_context(post, actor_id:, expected_hash:, expected_version:, extract:)
      surface = post.topic&.private_message? ? :private_message : :public_post
      actor = ::LinkSafety::RetryContext.actor_for(
        post,
        actor_id: actor_id,
        expected_hash: expected_hash,
        expected_version: expected_version,
      )
      extraction = extract ? ::LinkSafety::Extractor.post_raw_result(post.raw, post.topic_id, user: actor) : nil
      Context.new(
        surface: surface,
        actor: actor,
        private_content: ::LinkSafety::PrivacyContext.for_post(post),
        extraction: extraction,
      )
    end
    private_class_method :post_context

    def self.chat_context(message, actor_id:, expected_hash:, expected_version:, extract:)
      is_dm = ::Chat::Channel.direct_channel_chatable_types.include?(message.chat_channel&.chatable_type)
      surface = is_dm ? :chat_dm : :chat_public
      actor = ::LinkSafety::RetryContext.actor_for(
        message,
        actor_id: actor_id,
        expected_hash: expected_hash,
        expected_version: expected_version,
      )
      extraction =
        if extract
          ::LinkSafety::Extractor.chat_message_result(
            message.message,
            user: actor,
            author_username: message.user&.username,
          )
        end
      Context.new(
        surface: surface,
        actor: actor,
        private_content: ::LinkSafety::PrivacyContext.for_chat_message(message),
        extraction: extraction,
      )
    end
    private_class_method :chat_context

    def self.profile_context(profile, extract:)
      extraction =
        if extract
          urls = []
          urls << profile.website if profile.website.present?
          bio = ::LinkSafety::Extractor.markdown_result(profile.bio_raw)
          urls.concat(bio.urls)
          ::LinkSafety::Extractor::Extraction.new(
            urls: ::LinkSafety::UrlCandidateClassifier.filter(urls),
            error_code: bio.error_code,
          )
        end
      Context.new(
        surface: :profile,
        actor: profile.user,
        private_content: ::LinkSafety::PrivacyContext.for_user_profile(profile),
        extraction: extraction,
      )
    end
    private_class_method :profile_context

    def self.topic_context(topic, extract:)
      extraction =
        if extract
          ::LinkSafety::Extractor::Extraction.new(
            urls: ::LinkSafety::UrlCandidateClassifier.filter([topic.featured_link]),
            error_code: nil,
          )
        end
      Context.new(
        surface: :topic_featured_link,
        # A periodic check has no reliable editing actor. Do not attribute a
        # later provider verdict to the topic author.
        actor: nil,
        private_content: ::LinkSafety::PrivacyContext.for_topic(topic),
        extraction: extraction,
      )
    end
    private_class_method :topic_context

    def self.group_context(group, extract:)
      extraction = extract ? ::LinkSafety::Extractor.markdown_result(group.bio_raw) : nil
      Context.new(
        surface: :group_profile,
        actor: nil,
        private_content: ::LinkSafety::PrivacyContext.for_group(group),
        extraction: extraction,
      )
    end
    private_class_method :group_context
  end
end
