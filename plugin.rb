# frozen_string_literal: true

# name: Discourse-Link-Safety-Plugin
# about: Checks external links in Discourse content against configurable malicious URL reputation providers.
# version: 1.3.2
# authors: Chris

add_admin_route "admin.link_safety.title", "linkSafety"
enabled_site_setting :link_safety_enabled

module ::LinkSafety
  PLUGIN_NAME = "Discourse-Link-Safety-Plugin"
end


plugin_instance = self

after_initialize do
  %w[
    app/models/link_safety/cache_entry.rb
    app/models/link_safety/detection.rb
    app/models/link_safety/daily_stat.rb
  ].each { |path| require_dependency File.expand_path(path, __dir__) }

  %w[
    lib/link_safety/result.rb
    lib/link_safety/fingerprint.rb
    lib/link_safety/redis_namespace.rb
    lib/link_safety/canonicalizer.rb
    lib/link_safety/trusted_domains.rb
    lib/link_safety/site_origin.rb
    lib/link_safety/url_candidate_classifier.rb
    lib/link_safety/actor_resolver.rb
    lib/link_safety/authentication_context.rb
    lib/link_safety/retry_context.rb
    lib/link_safety/extractor.rb
    lib/link_safety/surface_policy.rb
    lib/link_safety/privacy_context.rb
    lib/link_safety/target_context.rb
    lib/link_safety/network_policy.rb
    lib/link_safety/lookup_budget.rb
    lib/link_safety/warning_presenter.rb
    lib/link_safety/verification_policy.rb
    lib/link_safety/circuit_breaker.rb
    lib/link_safety/health_registry.rb
    lib/link_safety/statistics.rb
    lib/link_safety/providers/base.rb
    lib/link_safety/providers/google_safe_browsing_v5.rb
    lib/link_safety/providers/google_web_risk.rb
    lib/link_safety/providers/urlhaus.rb
    lib/link_safety/checker.rb
    lib/link_safety/detection_recorder.rb
    lib/link_safety/content_validator.rb
    lib/link_safety/renderer.rb
    lib/link_safety/metadata_renderer.rb
    lib/link_safety/final_content_guard.rb
    lib/link_safety/final_content_verifier.rb
    lib/link_safety/onebox_gate.rb
    lib/link_safety/pending_scheduler.rb
    lib/link_safety/user_note_writer.rb
    lib/link_safety/admin_dashboard.rb
    app/services/problem_check/link_safety_operational_health.rb
  ].each { |path| require_relative path }

  register_problem_check ProblemCheck::LinkSafetyOperationalHealth

  %w[
    app/controllers/link_safety/admin_dashboard_controller.rb
    app/controllers/link_safety/admin_health_controller.rb
    app/controllers/link_safety/admin_detections_controller.rb
    app/controllers/link_safety/admin_statistics_controller.rb
  ].each { |path| require_dependency File.expand_path(path, __dir__) }

  if defined?(::DiscourseConnect)
    module ::LinkSafety
      module DiscourseConnectAuthenticationGuard
        def lookup_or_create_user(...)
          ::LinkSafety::AuthenticationContext.with_discourse_connect { super }
        end
      end
    end
    unless ::DiscourseConnect.ancestors.include?(::LinkSafety::DiscourseConnectAuthenticationGuard)
      ::DiscourseConnect.prepend(::LinkSafety::DiscourseConnectAuthenticationGuard)
    end
  end

  plugin_instance.validate("Post", :link_safety_validate_external_links) do
    next unless SiteSetting.link_safety_enabled
    next unless new_record? || will_save_change_to_raw?

    surface = topic&.private_message? ? :private_message : :public_post
    next unless ::LinkSafety::SurfacePolicy.enabled?(surface)

    actor = ::LinkSafety::ActorResolver.for_post(self)
    extraction = ::LinkSafety::Extractor.post_raw_result(raw, topic_id, user: actor)
    ::LinkSafety::ContentValidator.validate_model!(
      model: self,
      urls: extraction.urls,
      extraction_error: extraction.error_code,
      surface: surface,
      user: actor,
      private_content: ::LinkSafety::PrivacyContext.for_post(self),
    )
  end

  plugin_instance.add_model_callback("Post", :after_commit) do
    if SiteSetting.link_safety_enabled && (previous_changes.key?("id") || previous_changes.key?("raw"))
      ::LinkSafety::FinalContentGuard.persist_model_allowance!(self)
      ::LinkSafety::PendingScheduler.for_post(self)
    end
  end

  plugin_instance.validate("UserProfile", :link_safety_validate_profile_links) do
    next unless ::LinkSafety::SurfacePolicy.enabled?(:profile)

    website_changed = new_record? || will_save_change_to_website?
    bio_changed = new_record? || will_save_change_to_bio_raw?
    urls = []
    extraction_error = nil
    urls << website if website.present? && website_changed
    if bio_raw.present? && bio_changed
      extraction = ::LinkSafety::Extractor.markdown_result(bio_raw)
      urls.concat(extraction.urls)
      extraction_error ||= extraction.error_code
    end
    next if urls.blank? && extraction_error.blank?

    nonblocking = ::LinkSafety::AuthenticationContext.discourse_connect?
    ::LinkSafety::ContentValidator.validate_model!(
      model: self,
      urls: urls,
      extraction_error: extraction_error,
      surface: :profile,
      user: user,
      private_content: ::LinkSafety::PrivacyContext.for_user_profile(self),
      failure_policy: SiteSetting.link_safety_profile_fail_open ? :fail_open : :fail_closed,
      nonblocking: nonblocking,
    )

    if nonblocking && ::LinkSafety::ContentValidator.take_nonblocking_rejection!(self)
      # DiscourseConnect performs these profile saves while authenticating. Keep
      # the prior safe metadata if Link Safety rejects the incoming payload, but
      # never turn a metadata verdict/provider failure into an authentication
      # failure or redirect loop.
      self.website = attribute_in_database("website") if website_changed
      self.bio_raw = attribute_in_database("bio_raw") if bio_changed
    end
  end

  plugin_instance.validate("Topic", :link_safety_validate_featured_link) do
    next unless ::LinkSafety::SurfacePolicy.enabled?(:topic_featured_link)
    next unless featured_link.present? && (new_record? || will_save_change_to_featured_link?)

    actor = ::LinkSafety::ActorResolver.for_topic(self)
    ::LinkSafety::ContentValidator.validate_model!(
      model: self,
      urls: [featured_link],
      surface: :topic_featured_link,
      user: actor,
      private_content: ::LinkSafety::PrivacyContext.for_topic(self),
      failure_policy: SiteSetting.link_safety_metadata_fail_open ? :fail_open : :fail_closed,
    )
  end

  plugin_instance.validate("Group", :link_safety_validate_group_bio_links) do
    next unless ::LinkSafety::SurfacePolicy.enabled?(:group_profile)
    next if automatic
    next unless bio_raw.present? && (new_record? || will_save_change_to_bio_raw?)

    extraction = ::LinkSafety::Extractor.markdown_result(bio_raw)
    ::LinkSafety::ContentValidator.validate_model!(
      model: self,
      urls: extraction.urls,
      extraction_error: extraction.error_code,
      surface: :group_profile,
      private_content: ::LinkSafety::PrivacyContext.for_group(self),
      # Group does not expose the editing user at model-validation time. Do not
      # guess an owner and risk attributing a detection/User Note to the wrong
      # person; group changes still use the global lookup budget.
      user: nil,
      failure_policy: SiteSetting.link_safety_metadata_fail_open ? :fail_open : :fail_closed,
    )
  end

  if defined?(::Chat::Message)
    plugin_instance.validate("Chat::Message", :link_safety_validate_chat_links) do
      next unless SiteSetting.link_safety_enabled
      next unless new_record? || will_save_change_to_message?

      is_dm = ::Chat::Channel.direct_channel_chatable_types.include?(chat_channel&.chatable_type)
      surface = is_dm ? :chat_dm : :chat_public
      next unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      actor = ::LinkSafety::ActorResolver.for_chat_message(self)
      extraction = ::LinkSafety::Extractor.chat_message_result(
        message,
        user: actor,
        author_username: user&.username,
      )
      ::LinkSafety::ContentValidator.validate_model!(
        model: self,
        urls: extraction.urls,
        extraction_error: extraction.error_code,
        surface: surface,
        user: actor,
        private_content: ::LinkSafety::PrivacyContext.for_chat_message(self),
      )
    end

    plugin_instance.add_model_callback("Chat::Message", :after_commit) do
      if SiteSetting.link_safety_enabled && (previous_changes.key?("id") || previous_changes.key?("message"))
        ::LinkSafety::FinalContentGuard.persist_model_allowance!(self)
        ::LinkSafety::PendingScheduler.for_chat_message(self)
      end
    end

    # Chat has no event before onebox processing. Keep this patch deliberately
    # narrow: it only strips onebox-loading markers for URLs that already have
    # an explicit pending/error/threat verdict in the Link Safety cache, then
    # delegates all normal processing to Discourse.
    module ::LinkSafety
      module ChatMessageProcessorOneboxGate
        def post_process_oneboxes
          ::LinkSafety::OneboxGate.apply!(@doc, target: @model) if SiteSetting.link_safety_enabled
          super
        end
      end
    end
    unless ::Chat::MessageProcessor.ancestors.include?(::LinkSafety::ChatMessageProcessorOneboxGate)
      ::Chat::MessageProcessor.prepend(::LinkSafety::ChatMessageProcessorOneboxGate)
    end

    module ::LinkSafety
      module ChatMessageProcessorFinalGuard
        def run!(...)
          result = super
          ::LinkSafety::FinalContentGuard.apply!(@doc, target: @model) if SiteSetting.link_safety_enabled
          result
        end
      end
    end
    unless ::Chat::MessageProcessor.ancestors.include?(::LinkSafety::ChatMessageProcessorFinalGuard)
      ::Chat::MessageProcessor.prepend(::LinkSafety::ChatMessageProcessorFinalGuard)
    end
  end

  module ::LinkSafety
    module CookedPostProcessorFinalGuard
      def post_process(...)
        result = super
        ::LinkSafety::FinalContentGuard.apply!(@doc, target: @post) if SiteSetting.link_safety_enabled
        result
      end
    end
  end
  unless ::CookedPostProcessor.ancestors.include?(::LinkSafety::CookedPostProcessorFinalGuard)
    ::CookedPostProcessor.prepend(::LinkSafety::CookedPostProcessorFinalGuard)
  end

  if defined?(::LocalizedCookedPostProcessor)
    module ::LinkSafety
      module LocalizedCookedPostProcessorGuard
        def post_process(...)
          ::LinkSafety::OneboxGate.apply!(@doc, target: @post) if SiteSetting.link_safety_enabled
          result = super
          ::LinkSafety::FinalContentGuard.apply!(@doc, target: @post) if SiteSetting.link_safety_enabled
          result
        end
      end
    end
    unless ::LocalizedCookedPostProcessor.ancestors.include?(::LinkSafety::LocalizedCookedPostProcessorGuard)
      ::LocalizedCookedPostProcessor.prepend(::LinkSafety::LocalizedCookedPostProcessorGuard)
    end
  end

  # Metadata is guarded at presentation time rather than destructively editing
  # stored user/group/topic content. Existing serializer include/privacy methods
  # remain untouched; where a shared core presentation method exists we delegate
  # to it, and featured-link guards read the same model value the core serializer
  # would expose. Link Safety only changes returned navigation/HTML while cached
  # or fail-closed historical verification state requires it.
  module ::LinkSafety
    module UserProfileMetadataGuard
      def bio_processed
        ::LinkSafety::MetadataRenderer.render_html(super, surface: :profile)
      end

      def bio_excerpt(...)
        ::LinkSafety::MetadataRenderer.render_html(super, surface: :profile)
      end
    end

    module UserCardSerializerMetadataGuard
      def website
        ::LinkSafety::MetadataRenderer.safe_url(super, surface: :profile)
      end
    end

    module BasicGroupSerializerMetadataGuard
      def bio_cooked
        ::LinkSafety::MetadataRenderer.render_html(super, surface: :group_profile)
      end
    end

    module TopicListItemSerializerMetadataGuard
      def featured_link
        ::LinkSafety::MetadataRenderer.safe_url(object.featured_link, surface: :topic_featured_link)
      end
    end

    module SuggestedTopicSerializerMetadataGuard
      def featured_link
        ::LinkSafety::MetadataRenderer.safe_url(object.featured_link, surface: :topic_featured_link)
      end
    end

    module TopicViewSerializerMetadataGuard
      def featured_link
        ::LinkSafety::MetadataRenderer.safe_url(
          object.topic.featured_link,
          surface: :topic_featured_link,
        )
      end
    end
  end

  # Discourse's local user onebox reads profile fields directly instead of
  # going through UserSerializer/UserCardSerializer. Guard the completed local
  # onebox HTML as well so a revalidated profile threat cannot remain clickable
  # through that secondary presentation path. This is cache-only rendering and
  # never performs a provider lookup while cooking.
  if defined?(::Oneboxer)
    module ::LinkSafety
      module OneboxerUserProfileMetadataGuard
        def local_user_html(...)
          ::LinkSafety::MetadataRenderer.render_html(super, surface: :profile)
        end
      end
    end
    unless ::Oneboxer.singleton_class.ancestors.include?(::LinkSafety::OneboxerUserProfileMetadataGuard)
      ::Oneboxer.singleton_class.prepend(::LinkSafety::OneboxerUserProfileMetadataGuard)
    end
  end

  {
    ::UserProfile => ::LinkSafety::UserProfileMetadataGuard,
    ::UserCardSerializer => ::LinkSafety::UserCardSerializerMetadataGuard,
    ::BasicGroupSerializer => ::LinkSafety::BasicGroupSerializerMetadataGuard,
    ::TopicListItemSerializer => ::LinkSafety::TopicListItemSerializerMetadataGuard,
    ::SuggestedTopicSerializer => ::LinkSafety::SuggestedTopicSerializerMetadataGuard,
    ::TopicViewSerializer => ::LinkSafety::TopicViewSerializerMetadataGuard,
  }.each do |serializer, guard|
    serializer.prepend(guard) unless serializer.ancestors.include?(guard)
  end

  Plugin::Filter.register(:after_post_cook) do |post, cooked|
    if SiteSetting.link_safety_enabled
      ::LinkSafety::Renderer.render_html(cooked)
    else
      cooked
    end
  end

  on(:before_post_process_cooked) do |doc, post|
    ::LinkSafety::OneboxGate.apply!(doc, target: post) if SiteSetting.link_safety_enabled
  end

  Discourse::Application.routes.append do
    get "/admin/plugins/link-safety" => "admin/plugins#index", constraints: AdminConstraint.new
    get "/admin/plugins/link-safety-health" => "admin/plugins#index", constraints: AdminConstraint.new
    get "/admin/plugins/link-safety-detections" => "admin/plugins#index", constraints: AdminConstraint.new
    get "/admin/plugins/link-safety-statistics" => "admin/plugins#index", constraints: AdminConstraint.new

    get "/admin/plugins/link-safety/overview.json" => "link_safety/admin_dashboard#index",
        defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/link-safety/health.json" => "link_safety/admin_health#index",
        defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/link-safety/health/test.json" => "link_safety/admin_health#test",
         defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/link-safety/detections.json" => "link_safety/admin_detections#index",
        defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/link-safety/statistics.json" => "link_safety/admin_statistics#index",
        defaults: { format: :json }, constraints: AdminConstraint.new
  end
end
