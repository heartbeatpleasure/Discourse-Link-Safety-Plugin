# frozen_string_literal: true

module ::Jobs
  class LinkSafetyVerifyRenderedTarget < ::Jobs::Base
    MAX_ATTEMPTS = 5

    def execute(args)
      return unless SiteSetting.link_safety_enabled

      target = find_target(args[:target_type], args[:target_id])
      return unless target
      unless ::LinkSafety::RetryContext.matches_content?(
        target,
        args[:content_hash],
        expected_version: args[:content_version],
      )
        ::LinkSafety::FinalContentVerifier.release_schedule(
          target,
          content_hash: args[:content_hash],
          content_version: args[:content_version],
        )
        return
      end

      result = ::LinkSafety::FinalContentVerifier.verify!(
        target,
        revalidation: !!args[:revalidation],
      )
      retryable = result.errors.any? { |error| ::LinkSafety::VerificationPolicy.retryable?(error.error_code) }
      attempt = args[:attempt].to_i

      if retryable && attempt < MAX_ATTEMPTS
        Jobs.enqueue_in(
          [attempt * 2, 10].min.minutes,
          :link_safety_verify_rendered_target,
          target_type: args[:target_type],
          target_id: args[:target_id],
          attempt: attempt + 1,
          revalidation: !!args[:revalidation],
          content_hash: args[:content_hash],
          content_version: args[:content_version],
        )
      else
        ::LinkSafety::FinalContentVerifier.release_schedule(
          target,
          content_hash: args[:content_hash],
          content_version: args[:content_version],
        )
        ::LinkSafety::FinalContentVerifier.schedule_threat_refresh(target, result.threats) if result.threats.any?
      end
    end

    private

    def find_target(type, id)
      case type.to_s
      when "Post" then ::Post.find_by(id: id)
      when "UserProfile" then ::UserProfile.find_by(user_id: id)
      when "Topic" then ::Topic.find_by(id: id)
      when "Group" then ::Group.find_by(id: id)
      when "Chat::Message" then defined?(::Chat::Message) ? ::Chat::Message.find_by(id: id) : nil
      end
    end
  end
end
