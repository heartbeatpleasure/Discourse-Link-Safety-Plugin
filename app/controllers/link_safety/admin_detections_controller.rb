# frozen_string_literal: true

module ::LinkSafety
  class AdminDetectionsController < ::Admin::AdminController
    requires_plugin ::LinkSafety::PLUGIN_NAME
    before_action { response.headers["Cache-Control"] = "no-store" }

    def index
      limit = params[:limit].to_i.clamp(1, 200)
      limit = 50 if params[:limit].blank?
      rows = ::LinkSafety::Detection.includes(:user).order(detected_at: :desc).limit(limit)
      render_json_dump(
        generated_at: Time.zone.now,
        detections: rows.map { |row| serialize(row) },
      )
    end

    private

    def serialize(row)
      {
        id: row.id,
        detected_at: row.detected_at,
        provider: row.provider,
        host: row.host,
        threat_types: row.threat_types,
        surface: row.surface,
        action: row.action,
        user_id: row.user_id,
        username: row.user&.username,
        target_type: row.target_type,
        target_id: row.target_id,
      }
    end
  end
end
