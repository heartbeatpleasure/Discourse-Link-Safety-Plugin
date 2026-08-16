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
    elsif !SiteSetting.link_safety_google_user_protection_notice_acknowledged
      issues << I18n.t("link_safety.admin_alerts.google_user_protection_notice_not_acknowledged")
    end

    if provider == "web_risk_lookup" &&
         (SiteSetting.link_safety_scan_private_messages || SiteSetting.link_safety_scan_chat_direct_messages) &&
         !SiteSetting.link_safety_web_risk_private_surfaces
      issues << I18n.t("link_safety.admin_alerts.web_risk_private_surfaces_disabled")
    end

    if ::LinkSafety::CircuitBreaker.open?(provider)
      issues << I18n.t(
        "link_safety.admin_alerts.circuit_open",
        until_time: ::LinkSafety::CircuitBreaker.open_until(provider)&.iso8601,
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
end
