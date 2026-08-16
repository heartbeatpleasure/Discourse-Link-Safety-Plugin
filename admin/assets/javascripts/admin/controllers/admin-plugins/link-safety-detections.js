import Controller from "@ember/controller";
import { action } from "@ember/object";
import { service } from "@ember/service";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { i18n } from "discourse-i18n";

export default class AdminPluginsLinkSafetyDetectionsController extends Controller {
  @service currentUser;

  @tracked data = null;
  @tracked error = null;
  @tracked isLoading = false;

  formatDateTime(value) {
    if (!value) {
      return "—";
    }

    const timeZone = this.currentUser?.user_option?.timezone;
    const date = timeZone && moment.tz.zone(timeZone)
      ? moment(value).tz(timeZone)
      : moment(value);

    if (!date.isValid()) {
      return value;
    }

    const formatted = date.format(i18n("dates.long_with_year"));
    const zone = date.format("z");

    return zone ? `${formatted} (${zone})` : formatted;
  }

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
        detected_at_display: this.formatDateTime(row.detected_at),
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
