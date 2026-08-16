# frozen_string_literal: true

module ::LinkSafety
  class Detection < ::ActiveRecord::Base
    self.table_name = "link_safety_detections"
    belongs_to :user, optional: true

    validates :detected_at, :provider, :url_fingerprint, :host, :surface, :action, presence: true
  end
end
