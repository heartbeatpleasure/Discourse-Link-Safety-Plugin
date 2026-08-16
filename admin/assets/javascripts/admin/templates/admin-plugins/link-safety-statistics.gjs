import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/link-safety");

export default RouteTemplate(
  <template>
    <style>
      .ls-stats {
        --ls-surface: var(--secondary);
        --ls-surface-alt: var(--primary-very-low);
        --ls-border: var(--primary-low);
        --ls-muted: var(--primary-medium);
        display: flex;
        flex-direction: column;
        gap: 1rem;
        min-width: 0;
      }
      .ls-stats h1, .ls-stats h2, .ls-stats h3, .ls-stats h4, .ls-stats p { margin: 0; }
      .ls-stats__hero, .ls-stats__panel {
        min-width: 0;
        padding: 1.2rem 1.35rem;
        border: 1px solid var(--ls-border);
        border-radius: 18px;
        background: var(--ls-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .ls-stats__hero {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .ls-stats__copy {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .35rem;
      }
      .ls-stats__muted { color: var(--ls-muted); }
      .ls-stats__actions {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        align-items: center;
        justify-content: flex-end;
        gap: .5rem;
        margin-left: auto;
      }
      .ls-stats__actions .btn { white-space: nowrap; }
      .ls-stats__toolbar {
        display: flex;
        align-items: flex-end;
        justify-content: space-between;
        gap: 1rem;
      }
      .ls-stats__period-control {
        width: min(18rem, 100%);
        min-height: 42px;
        margin: 0;
        padding: 0 .85rem;
        border: 1px solid var(--ls-border);
        border-radius: 12px;
        background: var(--ls-surface-alt);
        color: var(--primary);
        box-sizing: border-box;
      }
      .ls-stats__summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
        gap: .75rem;
      }
      .ls-stats__summary-card {
        min-width: 0;
        padding: .8rem .9rem;
        border: 1px solid var(--ls-border);
        border-radius: 12px;
        background: var(--ls-surface-alt);
      }
      .ls-stats__summary-label {
        color: var(--ls-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .ls-stats__summary-value {
        margin-top: .2rem;
        font-size: var(--font-up-2);
        font-weight: 700;
        font-variant-numeric: tabular-nums;
      }
      .ls-stats__daily-list {
        display: grid;
        gap: .8rem;
        margin-top: .9rem;
      }
      .ls-stats__daily-card {
        min-width: 0;
        padding: .9rem;
        border: 1px solid var(--ls-border);
        border-radius: 14px;
        background: var(--ls-surface-alt);
      }
      .ls-stats__daily-header {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: 1rem;
        padding-bottom: .7rem;
        border-bottom: 1px solid var(--ls-border);
      }
      .ls-stats__daily-header h3 { font-size: var(--font-up-1); }
      .ls-stats__provider {
        color: var(--ls-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .ls-stats__daily-groups {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .65rem;
        margin-top: .7rem;
      }
      .ls-stats__daily-group {
        min-width: 0;
        padding: .7rem;
        border-radius: 11px;
        background: var(--secondary);
      }
      .ls-stats__daily-group h4 {
        margin-bottom: .55rem;
        color: var(--ls-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .ls-stats__daily-metrics {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .5rem .75rem;
      }
      .ls-stats__daily-metric { min-width: 0; }
      .ls-stats__daily-metric-label {
        color: var(--ls-muted);
        font-size: var(--font-down-2);
      }
      .ls-stats__daily-metric-value {
        margin-top: .08rem;
        font-weight: 700;
        font-variant-numeric: tabular-nums;
        overflow-wrap: anywhere;
      }
      .ls-stats__error {
        padding: .8rem 1rem;
        border: 1px solid var(--danger-low-mid);
        border-radius: 12px;
        background: var(--danger-low);
        color: var(--danger);
      }
      .ls-stats__empty {
        margin-top: .8rem;
        padding: 1rem;
        border-radius: 12px;
        background: var(--ls-surface-alt);
        color: var(--ls-muted);
      }
      @media (max-width: 1000px) {
        .ls-stats__daily-groups { grid-template-columns: 1fr 1fr; }
      }
      @media (max-width: 700px) {
        .ls-stats__hero { flex-direction: column; }
        .ls-stats__actions { justify-content: flex-start; margin-left: 0; }
        .ls-stats__toolbar { flex-direction: column; align-items: stretch; }
        .ls-stats__period-control { width: 100%; }
        .ls-stats__daily-groups { grid-template-columns: 1fr; }
        .ls-stats__daily-header { flex-direction: column; align-items: flex-start; gap: .25rem; }
      }
      @media (max-width: 460px) {
        .ls-stats__daily-metrics { grid-template-columns: 1fr; }
      }
    </style>

    <div class="ls-stats">
      <section class="ls-stats__hero">
        <div class="ls-stats__copy">
          <h1>{{i18n "admin.link_safety.open_statistics"}}</h1>
          <p class="ls-stats__muted">{{i18n "admin.link_safety.statistics_description"}}</p>
        </div>
        <div class="ls-stats__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.link_safety.back_to_overview"}}</a>
          <button class="btn btn-primary" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.load}}>
            {{i18n "admin.link_safety.refresh"}}
          </button>
        </div>
      </section>

      {{#if @controller.error}}
        <div class="ls-stats__error" role="alert">{{@controller.error}}</div>
      {{/if}}

      <section class="ls-stats__panel">
        <div class="ls-stats__toolbar">
          <div class="ls-stats__copy">
            <h2>{{i18n "admin.link_safety.period"}}</h2>
            <p class="ls-stats__muted">{{i18n "admin.link_safety.period_description"}}</p>
          </div>
          <select class="ls-stats__period-control" id="link-safety-statistics-period" value={{@controller.days}} aria-label={{i18n "admin.link_safety.period"}} disabled={{@controller.isLoading}} {{on "change" @controller.setDays}}>
            <option value="7">{{i18n "admin.link_safety.days_7"}}</option>
            <option value="30">{{i18n "admin.link_safety.days_30"}}</option>
            <option value="90">{{i18n "admin.link_safety.days_90"}}</option>
            <option value="365">{{i18n "admin.link_safety.days_365"}}</option>
          </select>
        </div>
      </section>

      {{#if @controller.data}}
        <section class="ls-stats__summary-grid">
          {{#each @controller.headlineCards as |card|}}
            <div class="ls-stats__summary-card">
              <div class="ls-stats__summary-label">{{card.label}}</div>
              <div class="ls-stats__summary-value">{{card.value}}</div>
            </div>
          {{/each}}
        </section>

        <section class="ls-stats__panel">
          <div class="ls-stats__copy">
            <h2>{{i18n "admin.link_safety.statistics_history"}}</h2>
            <p class="ls-stats__muted">{{i18n "admin.link_safety.daily_statistics_description"}}</p>
          </div>

          {{#if @controller.rows.length}}
            <div class="ls-stats__daily-list">
              {{#each @controller.rows as |row|}}
                <article class="ls-stats__daily-card">
                  <div class="ls-stats__daily-header">
                    <h3>{{row.date_display}}</h3>
                    <span class="ls-stats__provider">{{row.provider_display}}</span>
                  </div>

                  <div class="ls-stats__daily-groups">
                    <section class="ls-stats__daily-group">
                      <h4>{{i18n "admin.link_safety.group_protection"}}</h4>
                      <div class="ls-stats__daily-metrics">
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.checks"}}</div><div class="ls-stats__daily-metric-value">{{row.checks}}</div></div>
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.threat_count"}}</div><div class="ls-stats__daily-metric-value">{{row.threats}}</div></div>
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.blocked"}}</div><div class="ls-stats__daily-metric-value">{{row.blocked}}</div></div>
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.monitored"}}</div><div class="ls-stats__daily-metric-value">{{row.monitored}}</div></div>
                      </div>
                    </section>

                    <section class="ls-stats__daily-group">
                      <h4>{{i18n "admin.link_safety.group_provider"}}</h4>
                      <div class="ls-stats__daily-metrics">
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.provider_calls"}}</div><div class="ls-stats__daily-metric-value">{{row.provider_calls}}</div></div>
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.cache_hits"}}</div><div class="ls-stats__daily-metric-value">{{row.cache_hits}}</div></div>
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.trusted_skips"}}</div><div class="ls-stats__daily-metric-value">{{row.trusted_skips}}</div></div>
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.average_latency"}}</div><div class="ls-stats__daily-metric-value">{{row.average_latency_display}}</div></div>
                      </div>
                    </section>

                    <section class="ls-stats__daily-group">
                      <h4>{{i18n "admin.link_safety.group_reliability"}}</h4>
                      <div class="ls-stats__daily-metrics">
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.errors"}}</div><div class="ls-stats__daily-metric-value">{{row.errors}}</div></div>
                        <div class="ls-stats__daily-metric"><div class="ls-stats__daily-metric-label">{{i18n "admin.link_safety.fail_open"}}</div><div class="ls-stats__daily-metric-value">{{row.fail_open}}</div></div>
                      </div>
                    </section>
                  </div>
                </article>
              {{/each}}
            </div>
          {{else}}
            <div class="ls-stats__empty">{{i18n "admin.link_safety.no_data"}}</div>
          {{/if}}
        </section>
      {{else if @controller.isLoading}}
        <section class="ls-stats__panel"><p>{{i18n "admin.link_safety.loading"}}</p></section>
      {{/if}}
    </div>
  </template>
);
