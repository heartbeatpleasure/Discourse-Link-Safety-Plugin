import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { formatLinkSafetyDateTime } from "../../lib/link-safety-date";

export default class AdminPluginsLinkSafetyHealthController extends Controller {
  @tracked data = null;
  @tracked error = null;
  @tracked isLoading = false;
  @tracked isTesting = false;
  @tracked testResult = null;

  formatData(data) {
    if (!data) {
      return data;
    }

    return {
      ...data,
      last_success_at_display: formatLinkSafetyDateTime(data.last_success_at),
      last_failure_at_display: formatLinkSafetyDateTime(data.last_failure_at),
      circuit_open_until_display: formatLinkSafetyDateTime(
        data.circuit_open_until
      ),
    };
  }

  @action
  async load() {
    if (this.isLoading) {
      return;
    }

    this.isLoading = true;
    this.error = null;
    try {
      const data = await ajax("/admin/plugins/link-safety/health.json");
      this.data = this.formatData(data);
    } catch (e) {
      this.error =
        e?.jqXHR?.responseJSON?.errors?.[0] ||
        e?.message ||
        "Unable to load health data.";
    } finally {
      this.isLoading = false;
    }
  }

  @action
  async runTest() {
    if (this.isTesting) {
      return;
    }

    this.isTesting = true;
    this.testResult = null;
    this.error = null;
    try {
      this.testResult = await ajax(
        "/admin/plugins/link-safety/health/test.json",
        { type: "POST" }
      );
      await this.load();
    } catch (e) {
      this.error =
        e?.jqXHR?.responseJSON?.errors?.[0] ||
        e?.message ||
        "Provider test failed.";
    } finally {
      this.isTesting = false;
    }
  }
}
