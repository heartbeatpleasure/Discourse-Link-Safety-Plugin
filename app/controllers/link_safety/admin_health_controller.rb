# frozen_string_literal: true

module ::LinkSafety
  class AdminHealthController < ::Admin::AdminController
    requires_plugin ::LinkSafety::PLUGIN_NAME
    before_action { response.headers["Cache-Control"] = "no-store" }

    def index
      render_json_dump(::LinkSafety::AdminDashboard.overview)
    end

    def test
      RateLimiter.new(current_user, "link-safety-health-test", 4, 1.minute).performed!
      result = ::LinkSafety::Checker.check_many(
        ["https://example.com/"], surface: :admin_test, force: true,
        bypass_circuit: true, bypass_lookup_budget: true, user: current_user,
      ).first
      if result&.error?
        render_json_error(result.error_code.presence || "Provider test failed", status: 422)
      else
        render_json_dump(success: true, status: result&.status, provider: SiteSetting.link_safety_provider, checked_at: Time.zone.now)
      end
    end
  end
end
