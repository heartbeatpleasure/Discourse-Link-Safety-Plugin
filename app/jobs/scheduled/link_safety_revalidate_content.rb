# frozen_string_literal: true

module ::Jobs
  class LinkSafetyRevalidateContent < ::Jobs::Scheduled
    every 1.hour

    def execute(_args)
      return unless SiteSetting.link_safety_enabled
      return unless SiteSetting.link_safety_revalidation_enabled

      total = SiteSetting.link_safety_revalidation_targets_per_hour.to_i
      return if total <= 0

      scopes = eligible_scopes
      return if scopes.empty?

      base = total / scopes.length
      remainder = total % scopes.length
      scopes.each_with_index do |config, index|
        limit = base + (index < remainder ? 1 : 0)
        next if limit <= 0

        process_scope(**config, limit: limit)
      end
    rescue StandardError => e
      Rails.logger.warn("[LinkSafety] revalidation job failed class=#{e.class.name}")
      ::LinkSafety::HealthRegistry.control_failure!(component: :revalidation, code: e.class.name)
    end

    private

    def eligible_scopes
      scopes = []

      public_posts = ::LinkSafety::SurfacePolicy.enabled?(:public_post)
      private_messages = ::LinkSafety::SurfacePolicy.enabled?(:private_message)
      if public_posts || private_messages
        post_scope = ::Post.where(deleted_at: nil).where.not(topic_id: nil).joins(:topic)
        post_scope =
          if public_posts && private_messages
            post_scope
          elsif private_messages
            post_scope.where(topics: { archetype: Archetype.private_message })
          else
            post_scope.where.not(topics: { archetype: Archetype.private_message })
          end
        scopes << {
          scope: post_scope,
          cursor_name: "posts",
          cursor_column: :id,
        }

        if defined?(::PostLocalization)
          localization_scope =
            ::PostLocalization
              .joins(post: :topic)
              .where(posts: { deleted_at: nil })
              .where.not(raw: [nil, ""])
          localization_scope =
            if public_posts && private_messages
              localization_scope
            elsif private_messages
              localization_scope.where(topics: { archetype: Archetype.private_message })
            else
              localization_scope.where.not(topics: { archetype: Archetype.private_message })
            end
          scopes << {
            scope: localization_scope,
            cursor_name: "post_localizations",
            cursor_column: :id,
          }
        end
      end

      if defined?(::Chat::Message)
        public_chat = ::LinkSafety::SurfacePolicy.enabled?(:chat_public)
        direct_chat = ::LinkSafety::SurfacePolicy.enabled?(:chat_dm)
        if public_chat || direct_chat
          chat_types = []
          chat_types.concat(::Chat::Channel.public_channel_chatable_types) if public_chat
          chat_types.concat(::Chat::Channel.direct_channel_chatable_types) if direct_chat
          scopes << {
            scope:
              ::Chat::Message
                .where(deleted_at: nil)
                .joins(:chat_channel)
                .where(chat_channels: { chatable_type: chat_types.uniq }),
            cursor_name: "chat_messages",
            cursor_column: :id,
          }
        end
      end

      if ::LinkSafety::SurfacePolicy.enabled?(:profile)
        scopes << {
          scope:
            ::UserProfile.where(
              "(website IS NOT NULL AND website <> '') OR (bio_raw IS NOT NULL AND bio_raw <> '')",
            ),
          cursor_name: "user_profiles",
          cursor_column: :user_id,
        }
      end

      if ::LinkSafety::SurfacePolicy.enabled?(:topic_featured_link)
        scopes << {
          scope: ::Topic.where(deleted_at: nil).where.not(featured_link: [nil, ""]),
          cursor_name: "topic_featured_links",
          cursor_column: :id,
        }
      end

      if ::LinkSafety::SurfacePolicy.enabled?(:group_profile)
        scopes << {
          scope: ::Group.where(automatic: false).where.not(bio_raw: [nil, ""]),
          cursor_name: "group_profiles",
          cursor_column: :id,
        }
      end

      scopes
    end

    def process_scope(scope:, cursor_name:, cursor_column:, limit:)
      key = ::LinkSafety::RedisNamespace.key("revalidation_cursor", cursor_name)
      cursor = Discourse.redis.get(key).to_i
      table = scope.klass.arel_table
      records =
        scope
          .where(table[cursor_column].gt(cursor))
          .order(table[cursor_column].asc)
          .limit(limit)
          .to_a

      if records.empty?
        Discourse.redis.set(key, 0)
        return
      end

      records.each do |target|
        result = ::LinkSafety::FinalContentVerifier.verify!(target, revalidation: true)
        if result.errors.any? { |error| ::LinkSafety::VerificationPolicy.retryable?(error.error_code) }
          ::LinkSafety::FinalContentVerifier.schedule(target, revalidation: true)
        elsif result.threats.any?
          ::LinkSafety::FinalContentVerifier.schedule_threat_refresh(target, result.threats)
        end
      end
      Discourse.redis.set(key, records.last.public_send(cursor_column))
    end
  end
end
