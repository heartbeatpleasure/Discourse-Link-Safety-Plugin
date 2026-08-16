# frozen_string_literal: true

# name: Discourse-Link-Safety-Plugin
# about: Checks external links in Discourse content against configurable malicious URL reputation providers.
# version: 1.2.2
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
    lib/link_safety/canonicalizer.rb
    lib/link_safety/extractor.rb
    lib/link_safety/trusted_domains.rb
    lib/link_safety/surface_policy.rb
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

  plugin_instance.validate("Post", :link_safety_validate_external_links) do
    next unless SiteSetting.link_safety_enabled
    next unless new_record? || will_save_change_to_raw?

    surface = topic&.private_message? ? :private_message : :public_post
    next unless ::LinkSafety::SurfacePolicy.enabled?(surface)

    extraction = ::LinkSafety::Extractor.post_raw_result(raw, topic_id)
    ::LinkSafety::ContentValidator.validate_model!(
      model: self,
      urls: extraction.urls,
      extraction_error: extraction.error_code,
      surface: surface,
      user: user,
    )
  end

  plugin_instance.add_model_callback("Post", :after_commit) do
    if SiteSetting.link_safety_enabled && (previous_changes.key?("id") || previous_changes.key?("raw"))
      ::LinkSafety::PendingScheduler.for_post(self)
    end
  end

  plugin_instance.validate("UserProfile", :link_safety_validate_profile_links) do
    next unless ::LinkSafety::SurfacePolicy.enabled?(:profile)

    urls = []
    extraction_error = nil
    urls << website if website.present? && (new_record? || will_save_change_to_website?)
    if bio_raw.present? && (new_record? || will_save_change_to_bio_raw?)
      extraction = ::LinkSafety::Extractor.markdown_result(bio_raw)
      urls.concat(extraction.urls)
      extraction_error ||= extraction.error_code
    end
    next if urls.blank? && extraction_error.blank?

    ::LinkSafety::ContentValidator.validate_model!(
      model: self,
      urls: urls,
      extraction_error: extraction_error,
      surface: :profile,
      user: user,
      failure_policy: SiteSetting.link_safety_profile_fail_open ? :fail_open : :fail_closed,
    )
  end

  if defined?(::Chat::Message)
    plugin_instance.validate("Chat::Message", :link_safety_validate_chat_links) do
      next unless SiteSetting.link_safety_enabled
      next unless new_record? || will_save_change_to_message?

      is_dm = ::Chat::Channel.direct_channel_chatable_types.include?(chat_channel&.chatable_type)
      surface = is_dm ? :chat_dm : :chat_public
      next unless ::LinkSafety::SurfacePolicy.enabled?(surface)

      extraction = ::LinkSafety::Extractor.chat_message_result(message, user: user)
      ::LinkSafety::ContentValidator.validate_model!(
        model: self,
        urls: extraction.urls,
        extraction_error: extraction.error_code,
        surface: surface,
        user: user,
      )
    end

    plugin_instance.add_model_callback("Chat::Message", :after_commit) do
      if SiteSetting.link_safety_enabled && (previous_changes.key?("id") || previous_changes.key?("message"))
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
          ::LinkSafety::OneboxGate.apply!(@doc) if SiteSetting.link_safety_enabled
          super
        end
      end
    end
    unless ::Chat::MessageProcessor.ancestors.include?(::LinkSafety::ChatMessageProcessorOneboxGate)
      ::Chat::MessageProcessor.prepend(::LinkSafety::ChatMessageProcessorOneboxGate)
    end
  end

  Plugin::Filter.register(:after_post_cook) do |post, cooked|
    if SiteSetting.link_safety_enabled
      ::LinkSafety::Renderer.render_html(cooked)
    else
      cooked
    end
  end

  on(:before_post_process_cooked) do |doc, _post|
    ::LinkSafety::OneboxGate.apply!(doc) if SiteSetting.link_safety_enabled
  end

  on(:chat_message_processed) do |doc, _message|
    ::LinkSafety::Renderer.render_document!(doc) if SiteSetting.link_safety_enabled
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
