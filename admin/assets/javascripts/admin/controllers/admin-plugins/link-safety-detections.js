import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { formatLinkSafetyDateTime } from "../../lib/link-safety-date";

export default class AdminPluginsLinkSafetyDetectionsController extends Controller {
  @tracked data = null;
  @tracked error = null;
  @tracked isLoading = false;

  @action
  async load() {
    if (this.isLoading) {
      return;
    }

    this.isLoading = true;
    this.error = null;

    try {
      const data = await ajax(
        "/admin/plugins/link-safety/detections.json?limit=100"
      );
      data.detections = (data.detections || []).map((row) => ({
        ...row,
        detected_at_display: formatLinkSafetyDateTime(row.detected_at),
      }));
      this.data = data;
    } catch (e) {
      this.error =
        e?.jqXHR?.responseJSON?.errors?.[0] ||
        e?.message ||
        "Unable to load detections.";
    } finally {
      this.isLoading = false;
    }
  }
}
