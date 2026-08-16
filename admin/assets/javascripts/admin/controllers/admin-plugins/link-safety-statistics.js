import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";

export default class AdminPluginsLinkSafetyStatisticsController extends Controller {
  @tracked data = null; @tracked error = null; @tracked isLoading = false; @tracked days = 30;
  @action async load() {
    if (this.isLoading) return; this.isLoading = true; this.error = null;
    try { this.data = await ajax(`/admin/plugins/link-safety/statistics.json?days=${this.days}`); }
    catch (e) { this.error = e?.jqXHR?.responseJSON?.errors?.[0] || e?.message || "Unable to load statistics."; }
    finally { this.isLoading = false; }
  }
  @action async setDays(event) { this.days = Number(event.target.value || 30); await this.load(); }
}
