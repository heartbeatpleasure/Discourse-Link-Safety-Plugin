# frozen_string_literal: true

class ProblemCheck::LinkSafetyOperationalHealth < ProblemCheck
  self.priority = "high"
  self.perform_every = 10.minutes
  self.max_retries = 0
  self.max_blips = 1

  def call
    return no_problem unless SiteSetting.link_safety_enabled

    issues = []
    provider = SiteSetting.link_safety_provider.to_s

    if SiteSetting.link_safety_google_api_key.blank?
      issues << I18n.t("link_safety.admin_alerts.missing_api_key")
    elsif provider == "safe_browsing_v5" && !SiteSetting.link_safety_safe_browsing_noncommercial_acknowledged
      issues << I18n.t("link_safety.admin_alerts.safe_browsing_usage_not_acknowledged")
    end

    private_content_possible =
      if provider == "web_risk_lookup" || SiteSetting.link_safety_urlhaus_enabled
        private_content_scanning_possible?
      else
        false
      end
    if provider == "web_risk_lookup" && private_content_possible &&
         !SiteSetting.link_safety_web_risk_private_surfaces
      issues << I18n.t("link_safety.admin_alerts.web_risk_private_surfaces_disabled")
    end

    if SiteSetting.link_safety_urlhaus_enabled && SiteSetting.link_safety_urlhaus_auth_key.blank?
      issues << I18n.t("link_safety.admin_alerts.missing_urlhaus_auth_key")
    elsif SiteSetting.link_safety_urlhaus_enabled && private_content_possible &&
          !SiteSetting.link_safety_urlhaus_private_surfaces
      issues << I18n.t("link_safety.admin_alerts.urlhaus_private_surfaces_disabled")
    end

    if ::LinkSafety::CircuitBreaker.open?(provider)
      issues << I18n.t(
        "link_safety.admin_alerts.circuit_open",
        until_time: ::LinkSafety::CircuitBreaker.open_until(provider)&.iso8601,
      )
    end

    if SiteSetting.link_safety_urlhaus_enabled && ::LinkSafety::CircuitBreaker.open?("urlhaus")
      issues << I18n.t(
        "link_safety.admin_alerts.circuit_open",
        until_time: ::LinkSafety::CircuitBreaker.open_until("urlhaus")&.iso8601,
      )
    end

    control_failures = ::LinkSafety::HealthRegistry.control_failures
    if control_failures.any?
      summary = control_failures.map { |entry| "#{entry[:component]} (#{entry[:count]})" }.join(", ")
      issues << I18n.t("link_safety.admin_alerts.security_control_failures", summary: summary)
    end

    return no_problem if issues.empty?

    html = "<ul>#{issues.map { |issue| "<li>#{ERB::Util.html_escape(issue)}</li>" }.join}</ul>"
    problem(
      override_data: { issues: html },
      details: { issues: html, provider: provider },
    )
  end
  private

  def private_content_scanning_possible?
    return true if SiteSetting.respond_to?(:login_required) && SiteSetting.login_required
    return true if SiteSetting.link_safety_scan_private_messages
    return true if SiteSetting.link_safety_scan_chat_direct_messages

    if SiteSetting.link_safety_scan_profile_links
      return true if SiteSetting.respond_to?(:hide_user_profiles_from_public) &&
        SiteSetting.hide_user_profiles_from_public
      return true if SiteSetting.respond_to?(:allow_users_to_hide_profile) &&
        SiteSetting.allow_users_to_hide_profile
      return true if SiteSetting.respond_to?(:hide_new_user_profiles) && SiteSetting.hide_new_user_profiles
    end

    secure_category_surface =
      SiteSetting.link_safety_scan_public_posts || SiteSetting.link_safety_scan_chat_public ||
        SiteSetting.link_safety_scan_topic_featured_links
    return true if secure_category_surface && ::Category.where(read_restricted: true).exists?

    if SiteSetting.link_safety_scan_group_bio_links
      public_level = ::Group.visibility_levels[:public]
      return true if ::Group.where(automatic: false).where.not(visibility_level: public_level).exists?
    end

    false
  rescue StandardError => e
    Rails.logger.warn("[LinkSafety] private-content health classification failed class=#{e.class.name}")
    # A health check should be conservative: if privacy classification itself
    # cannot be established, warn rather than claiming full-URL sharing is safe.
    true
  end

end
