import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/link-safety");

export default RouteTemplate(
  <template>
    <style>
      .ls-detections {
        --ls-surface: var(--secondary);
        --ls-border: var(--primary-low);
        --ls-muted: var(--primary-medium);
        display: flex;
        flex-direction: column;
        gap: 1rem;
        min-width: 0;
      }
      .ls-detections h1, .ls-detections h2, .ls-detections p { margin: 0; }
      .ls-detections__hero, .ls-detections__panel {
        min-width: 0;
        padding: 1.2rem 1.35rem;
        border: 1px solid var(--ls-border);
        border-radius: 18px;
        background: var(--ls-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .ls-detections__hero {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .ls-detections__copy {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .35rem;
      }
      .ls-detections__muted { color: var(--ls-muted); }
      .ls-detections__actions {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        align-items: center;
        justify-content: flex-end;
        gap: .5rem;
        margin-left: auto;
      }
      .ls-detections__table-wrap {
        overflow: auto;
        margin-top: .8rem;
        border: 1px solid var(--ls-border);
        border-radius: 12px;
      }
      .ls-detections__table-wrap table { width: 100%; margin: 0; }
      .ls-detections__table-wrap th, .ls-detections__table-wrap td {
        vertical-align: top;
        white-space: nowrap;
      }
      .ls-detections__table-wrap td:nth-child(2),
      .ls-detections__table-wrap td:nth-child(3) {
        max-width: 26rem;
        white-space: normal;
        overflow-wrap: anywhere;
      }
      .ls-detections__error {
        padding: .8rem 1rem;
        border: 1px solid var(--danger-low-mid);
        border-radius: 12px;
        background: var(--danger-low);
        color: var(--danger);
      }
      .ls-detections__empty {
        margin-top: .8rem;
        padding: 1rem;
        border-radius: 12px;
        background: var(--primary-very-low);
        color: var(--ls-muted);
      }
      @media (max-width: 700px) {
        .ls-detections__hero { flex-direction: column; }
        .ls-detections__actions { justify-content: flex-start; margin-left: 0; }
      }
    </style>

    <div class="ls-detections">
      <section class="ls-detections__hero">
        <div class="ls-detections__copy">
          <h1>{{i18n "admin.link_safety.open_detections"}}</h1>
          <p class="ls-detections__muted">{{i18n "admin.link_safety.detections_description"}}</p>
        </div>
        <div class="ls-detections__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.link_safety.back_to_overview"}}</a>
          <button class="btn btn-primary" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.load}}>
            {{i18n "admin.link_safety.refresh"}}
          </button>
        </div>
      </section>

      {{#if @controller.error}}
        <div class="ls-detections__error" role="alert">{{@controller.error}}</div>
      {{/if}}

      <section class="ls-detections__panel">
        <h2>{{i18n "admin.link_safety.detection_history"}}</h2>
        {{#if @controller.data.detections.length}}
          <div class="ls-detections__table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>{{i18n "admin.link_safety.date"}}</th>
                  <th>{{i18n "admin.link_safety.host"}}</th>
                  <th>{{i18n "admin.link_safety.threats"}}</th>
                  <th>{{i18n "admin.link_safety.surface"}}</th>
                  <th>{{i18n "admin.link_safety.action"}}</th>
                  <th>{{i18n "admin.link_safety.username"}}</th>
                </tr>
              </thead>
              <tbody>
                {{#each @controller.data.detections as |row|}}
                  <tr>
                    <td>{{row.detected_at_display}}</td>
                    <td>{{row.host}}</td>
                    <td>{{row.threat_types}}</td>
                    <td>{{row.surface}}</td>
                    <td>{{row.action}}</td>
                    <td>{{row.username}}</td>
                  </tr>
                {{/each}}
              </tbody>
            </table>
          </div>
        {{else if @controller.data}}
          <div class="ls-detections__empty">{{i18n "admin.link_safety.no_detections"}}</div>
        {{else}}
          <div class="ls-detections__empty">{{i18n "admin.link_safety.loading"}}</div>
        {{/if}}
      </section>
    </div>
  </template>
);
