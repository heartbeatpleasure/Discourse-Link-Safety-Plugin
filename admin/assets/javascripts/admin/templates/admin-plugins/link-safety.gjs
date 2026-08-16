import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const settingsUrl = getURL(
  "/admin/site_settings/category/all_results?filter=link_safety"
);
const healthUrl = getURL("/admin/plugins/link-safety-health");
const detectionsUrl = getURL("/admin/plugins/link-safety-detections");
const statisticsUrl = getURL("/admin/plugins/link-safety-statistics");

export default RouteTemplate(
  <template>
    <style>
      .ls-admin {
        --ls-surface: var(--secondary);
        --ls-border: var(--primary-low);
        --ls-muted: var(--primary-medium);
        display: flex;
        flex-direction: column;
        gap: 1rem;
        min-width: 0;
      }
      .ls-admin h1, .ls-admin h2, .ls-admin h3, .ls-admin p { margin: 0; }
      .ls-admin__hero, .ls-admin__card, .ls-admin__metric {
        border: 1px solid var(--ls-border);
        border-radius: 18px;
        background: var(--ls-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .ls-admin__hero {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
        padding: 1.25rem 1.35rem;
      }
      .ls-admin__hero-copy {
        display: grid;
        min-width: 0;
        flex: 1 1 auto;
        gap: .45rem;
        max-width: 760px;
      }
      .ls-admin__hero > .btn {
        flex: 0 0 auto;
        margin-left: auto;
        white-space: nowrap;
      }
      .ls-admin__hero-copy p, .ls-admin__muted, .ls-admin__card p {
        color: var(--ls-muted);
      }
      .ls-admin__section { display: grid; gap: .7rem; }
      .ls-admin__status-row {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .8rem;
      }
      .ls-admin__metric { min-width: 0; padding: .85rem 1rem; }
      .ls-admin__metric-label {
        color: var(--ls-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .ls-admin__metric-value {
        margin-top: .25rem;
        font-size: var(--font-up-2);
        font-weight: 700;
        overflow-wrap: anywhere;
      }
      .ls-admin__grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 1rem;
      }
      .ls-admin__card {
        display: flex;
        min-height: 165px;
        flex-direction: column;
        gap: .8rem;
        padding: 1rem 1.1rem;
        color: var(--primary);
        text-decoration: none;
        transition: border-color .12s ease, box-shadow .12s ease, transform .12s ease;
      }
      .ls-admin__card:hover, .ls-admin__card:focus {
        border-color: var(--tertiary-medium);
        box-shadow: 0 6px 18px rgb(0 0 0 / 6%);
        color: var(--primary);
        text-decoration: none;
        transform: translateY(-1px);
      }
      .ls-admin__card.is-primary {
        border-color: var(--tertiary-low);
        background: linear-gradient(180deg, var(--secondary), var(--tertiary-very-low));
      }
      .ls-admin__badge {
        display: inline-flex;
        width: max-content;
        padding: .35rem .55rem;
        border: 1px solid var(--primary-low);
        border-radius: 999px;
        background: var(--primary-very-low);
        color: var(--primary-medium);
        font-size: var(--font-down-1);
        line-height: 1;
      }
      .ls-admin__badge.is-primary {
        border-color: var(--tertiary-low);
        background: var(--tertiary-low);
        color: var(--tertiary);
      }
      .ls-admin__action {
        margin-top: auto;
        color: var(--tertiary);
        font-weight: 600;
      }
      @media (max-width: 850px) {
        .ls-admin__status-row { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      @media (max-width: 700px) {
        .ls-admin__hero { flex-direction: column; }
        .ls-admin__hero > .btn { align-self: flex-end; margin-left: 0; }
      }
      @media (max-width: 600px) {
        .ls-admin__status-row { grid-template-columns: 1fr; }
      }
    </style>

    <div class="ls-admin">
      <section class="ls-admin__hero">
        <div class="ls-admin__hero-copy">
          <h1>{{i18n "admin.link_safety.title"}}</h1>
          <p>{{i18n "admin.link_safety.description"}}</p>
        </div>
        <a class="btn btn-primary" href={{settingsUrl}}>
          {{i18n "admin.link_safety.open_settings"}}
        </a>
      </section>

      <section class="ls-admin__section">
        <div>
          <h2>{{i18n "admin.link_safety.current_status"}}</h2>
          <p class="ls-admin__muted">{{i18n "admin.link_safety.current_status_description"}}</p>
        </div>
        <div class="ls-admin__status-row">
          <div class="ls-admin__metric">
            <div class="ls-admin__metric-label">{{i18n "admin.link_safety.status"}}</div>
            <div class="ls-admin__metric-value">
              {{if @model.enabled (i18n "admin.link_safety.enabled") (i18n "admin.link_safety.disabled")}}
            </div>
          </div>
          <div class="ls-admin__metric">
            <div class="ls-admin__metric-label">{{i18n "admin.link_safety.provider"}}</div>
            <div class="ls-admin__metric-value">{{@model.provider}}</div>
          </div>
          <div class="ls-admin__metric">
            <div class="ls-admin__metric-label">{{i18n "admin.link_safety.mode"}}</div>
            <div class="ls-admin__metric-value">{{@model.mode}}</div>
          </div>
          <div class="ls-admin__metric">
            <div class="ls-admin__metric-label">{{i18n "admin.link_safety.circuit"}}</div>
            <div class="ls-admin__metric-value">
              {{if @model.circuit_open (i18n "admin.link_safety.circuit_open") (i18n "admin.link_safety.circuit_closed")}}
            </div>
          </div>
        </div>
      </section>

      <section class="ls-admin__section">
        <div>
          <h2>{{i18n "admin.link_safety.overview_title"}}</h2>
          <p class="ls-admin__muted">{{i18n "admin.link_safety.overview_description"}}</p>
        </div>
        <div class="ls-admin__grid">
          <a class="ls-admin__card is-primary" href={{settingsUrl}}>
            <span class="ls-admin__badge is-primary">{{i18n "admin.link_safety.category_configuration"}}</span>
            <h3>{{i18n "admin.link_safety.open_settings"}}</h3>
            <p>{{i18n "admin.link_safety.settings_description"}}</p>
            <span class="ls-admin__action">{{i18n "admin.link_safety.open_tool"}}</span>
          </a>
          <a class="ls-admin__card" href={{healthUrl}}>
            <span class="ls-admin__badge">{{i18n "admin.link_safety.category_monitoring"}}</span>
            <h3>{{i18n "admin.link_safety.open_health"}}</h3>
            <p>{{i18n "admin.link_safety.health_description"}}</p>
            <span class="ls-admin__action">{{i18n "admin.link_safety.open_tool"}}</span>
          </a>
          <a class="ls-admin__card" href={{detectionsUrl}}>
            <span class="ls-admin__badge">{{i18n "admin.link_safety.category_security"}}</span>
            <h3>{{i18n "admin.link_safety.open_detections"}}</h3>
            <p>{{i18n "admin.link_safety.detections_description"}}</p>
            <span class="ls-admin__action">{{i18n "admin.link_safety.open_tool"}}</span>
          </a>
          <a class="ls-admin__card" href={{statisticsUrl}}>
            <span class="ls-admin__badge">{{i18n "admin.link_safety.category_reporting"}}</span>
            <h3>{{i18n "admin.link_safety.open_statistics"}}</h3>
            <p>{{i18n "admin.link_safety.statistics_description"}}</p>
            <span class="ls-admin__action">{{i18n "admin.link_safety.open_tool"}}</span>
          </a>
        </div>
      </section>
    </div>
  </template>
);
