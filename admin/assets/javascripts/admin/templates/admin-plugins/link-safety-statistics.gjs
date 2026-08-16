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
        --ls-border: var(--primary-low);
        --ls-muted: var(--primary-medium);
        display: flex;
        flex-direction: column;
        gap: 1rem;
        min-width: 0;
      }
      .ls-stats h1, .ls-stats h2, .ls-stats p { margin: 0; }
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
        flex-direction: column;
        align-items: flex-end;
        justify-content: flex-start;
        gap: .8rem;
        margin-left: auto;
      }
      .ls-stats__buttons {
        display: flex;
        flex-wrap: wrap;
        justify-content: flex-end;
        gap: .5rem;
      }
      .ls-stats__period {
        display: inline-flex;
        align-items: center;
        gap: .75rem;
        margin: 5px 0 0;
      }
      .ls-stats__period > span {
        color: var(--ls-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .ls-stats__period select {
        min-width: 180px;
        min-height: 38px;
        padding: 0 .65rem;
        border: 1px solid var(--ls-border);
        border-radius: 8px;
        background: var(--secondary);
        color: var(--primary);
      }
      .ls-stats__table-wrap {
        overflow: auto;
        margin-top: .8rem;
        border: 1px solid var(--ls-border);
        border-radius: 12px;
      }
      .ls-stats__table-wrap table { width: 100%; margin: 0; }
      .ls-stats__table-wrap th, .ls-stats__table-wrap td {
        vertical-align: top;
        white-space: nowrap;
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
        background: var(--primary-very-low);
        color: var(--ls-muted);
      }
      @media (max-width: 700px) {
        .ls-stats__hero { flex-direction: column; }
        .ls-stats__actions { align-items: flex-start; justify-content: flex-start; margin-left: 0; }
        .ls-stats__buttons { justify-content: flex-start; }
        .ls-stats__period { width: 100%; }
        .ls-stats__period select { min-width: 0; flex: 1 1 auto; }
      }
    </style>

    <div class="ls-stats">
      <section class="ls-stats__hero">
        <div class="ls-stats__copy">
          <h1>{{i18n "admin.link_safety.open_statistics"}}</h1>
          <p class="ls-stats__muted">{{i18n "admin.link_safety.statistics_description"}}</p>
        </div>
        <div class="ls-stats__actions">
          <div class="ls-stats__buttons">
            <a class="btn" href={{overviewUrl}}>{{i18n "admin.link_safety.back_to_overview"}}</a>
            <button class="btn btn-primary" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.load}}>
              {{i18n "admin.link_safety.refresh"}}
            </button>
          </div>
          <label class="ls-stats__period" for="link-safety-statistics-period">
            <span>{{i18n "admin.link_safety.period"}}</span>
            <select id="link-safety-statistics-period" value={{@controller.days}} aria-label={{i18n "admin.link_safety.period"}} disabled={{@controller.isLoading}} {{on "change" @controller.setDays}}>
              <option value="7">7 days</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="365">365 days</option>
            </select>
          </label>
        </div>
      </section>

      {{#if @controller.error}}
        <div class="ls-stats__error" role="alert">{{@controller.error}}</div>
      {{/if}}

      <section class="ls-stats__panel">
        <h2>{{i18n "admin.link_safety.statistics_history"}}</h2>
        {{#if @controller.data.rows.length}}
          <div class="ls-stats__table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>{{i18n "admin.link_safety.date"}}</th>
                  <th>{{i18n "admin.link_safety.provider"}}</th>
                  <th>{{i18n "admin.link_safety.checks"}}</th>
                  <th>{{i18n "admin.link_safety.provider_calls"}}</th>
                  <th>{{i18n "admin.link_safety.cache_hits"}}</th>
                  <th>{{i18n "admin.link_safety.trusted_skips"}}</th>
                  <th>{{i18n "admin.link_safety.threat_count"}}</th>
                  <th>{{i18n "admin.link_safety.blocked"}}</th>
                  <th>{{i18n "admin.link_safety.monitored"}}</th>
                  <th>{{i18n "admin.link_safety.errors"}}</th>
                  <th>{{i18n "admin.link_safety.fail_open"}}</th>
                </tr>
              </thead>
              <tbody>
                {{#each @controller.data.rows as |row|}}
                  <tr>
                    <td>{{row.date}}</td>
                    <td>{{row.provider}}</td>
                    <td>{{row.checks}}</td>
                    <td>{{row.provider_calls}}</td>
                    <td>{{row.cache_hits}}</td>
                    <td>{{row.trusted_skips}}</td>
                    <td>{{row.threats}}</td>
                    <td>{{row.blocked}}</td>
                    <td>{{row.monitored}}</td>
                    <td>{{row.errors}}</td>
                    <td>{{row.fail_open}}</td>
                  </tr>
                {{/each}}
              </tbody>
            </table>
          </div>
        {{else if @controller.data}}
          <div class="ls-stats__empty">{{i18n "admin.link_safety.no_data"}}</div>
        {{else}}
          <div class="ls-stats__empty">{{i18n "admin.link_safety.loading"}}</div>
        {{/if}}
      </section>
    </div>
  </template>
);
