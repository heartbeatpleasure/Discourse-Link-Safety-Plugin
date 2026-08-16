import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";

export default class AdminPluginsLinkSafetyDetectionsController extends Controller {
  @tracked data = null; @tracked error = null; @tracked isLoading = false;
  @action async load() {
    if (this.isLoading) return; this.isLoading = true; this.error = null;
    try { this.data = await ajax("/admin/plugins/link-safety/detections.json?limit=100"); }
    catch (e) { this.error = e?.jqXHR?.responseJSON?.errors?.[0] || e?.message || "Unable to load detections."; }
    finally { this.isLoading = false; }
  }
}
