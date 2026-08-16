# frozen_string_literal: true

module ::LinkSafety
  class AdminDashboardController < ::Admin::AdminController
    requires_plugin ::LinkSafety::PLUGIN_NAME
    before_action { response.headers["Cache-Control"] = "no-store" }

    def index
      render_json_dump(::LinkSafety::AdminDashboard.overview)
    end
  end
end
