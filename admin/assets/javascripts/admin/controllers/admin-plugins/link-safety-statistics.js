import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import {
  formatLinkSafetyDateOnly,
} from "../../lib/link-safety-date";
import { i18n } from "discourse-i18n";

const SUM_FIELDS = [
  "checks",
  "provider_calls",
  "cache_hits",
  "trusted_skips",
  "threats",
  "blocked",
  "monitored",
  "errors",
  "fail_open",
];

export default class AdminPluginsLinkSafetyStatisticsController extends Controller {
  @tracked data = null;
  @tracked error = null;
  @tracked isLoading = false;
  @tracked days = 30;

  get rows() {
    return this.data?.rows || [];
  }

  get totals() {
    const totals = Object.fromEntries(SUM_FIELDS.map((field) => [field, 0]));
    for (const row of this.rows) {
      for (const field of SUM_FIELDS) {
        totals[field] += Number(row[field] || 0);
      }
    }
    return totals;
  }

  get headlineCards() {
    const totals = this.totals;
    return [
      { label: i18n("admin.link_safety.checks"), value: totals.checks },
      {
        label: i18n("admin.link_safety.provider_calls"),
        value: totals.provider_calls,
      },
      { label: i18n("admin.link_safety.cache_hits"), value: totals.cache_hits },
      { label: i18n("admin.link_safety.threat_count"), value: totals.threats },
      { label: i18n("admin.link_safety.blocked"), value: totals.blocked },
      { label: i18n("admin.link_safety.monitored"), value: totals.monitored },
      { label: i18n("admin.link_safety.errors"), value: totals.errors },
      { label: i18n("admin.link_safety.fail_open"), value: totals.fail_open },
    ];
  }

  providerDisplay(provider) {
    switch (provider) {
      case "safe_browsing_v5":
        return i18n("admin.link_safety.provider_safe_browsing_v5");
      case "web_risk_lookup":
        return i18n("admin.link_safety.provider_web_risk");
      case "urlhaus":
        return "URLhaus";
      default:
        return provider || "—";
    }
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
        `/admin/plugins/link-safety/statistics.json?days=${this.days}`
      );
      this.data = {
        ...data,
        rows: (data?.rows || []).map((row) => ({
          ...row,
          date_display: formatLinkSafetyDateOnly(row.date),
          provider_display: this.providerDisplay(row.provider),
          average_latency_display:
            row.average_latency_ms === null ||
            row.average_latency_ms === undefined
              ? "—"
              : `${row.average_latency_ms} ms`,
        })),
      };
    } catch (e) {
      this.error =
        e?.jqXHR?.responseJSON?.errors?.[0] ||
        e?.message ||
        "Unable to load statistics.";
    } finally {
      this.isLoading = false;
    }
  }

  @action
  async setDays(event) {
    this.days = Number(event.target.value || 30);
    await this.load();
  }
}
