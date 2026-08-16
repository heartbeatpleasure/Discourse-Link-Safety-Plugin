import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/link-safety");
const settingsUrl = getURL(
  "/admin/site_settings/category/all_results?filter=link_safety"
);

export default RouteTemplate(
  <template>
    <style>
      .ls-health {
        --ls-surface: var(--secondary);
        --ls-surface-alt: var(--primary-very-low);
        --ls-border: var(--primary-low);
        --ls-muted: var(--primary-medium);
        display: flex;
        flex-direction: column;
        gap: 1rem;
        min-width: 0;
      }
      .ls-health h1, .ls-health h2, .ls-health p { margin: 0; }
      .ls-health__hero, .ls-health__panel {
        min-width: 0;
        padding: 1.2rem 1.35rem;
        border: 1px solid var(--ls-border);
        border-radius: 18px;
        background: var(--ls-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .ls-health__hero {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .ls-health__copy {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .35rem;
      }
      .ls-health__muted { color: var(--ls-muted); }
      .ls-health__actions {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        align-items: center;
        justify-content: flex-end;
        gap: .5rem;
        margin-left: auto;
      }
      .ls-health__actions .btn { white-space: nowrap; }
      .ls-health__grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .75rem;
        margin-top: .85rem;
      }
      .ls-health__item {
        min-width: 0;
        padding: .8rem;
        border: 1px solid var(--ls-border);
        border-radius: 12px;
        background: var(--ls-surface-alt);
      }
      .ls-health__label {
        color: var(--ls-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .ls-health__value {
        margin-top: .22rem;
        overflow-wrap: anywhere;
        font-weight: 700;
      }
      .ls-health__error, .ls-health__success {
        padding: .8rem 1rem;
        border-radius: 12px;
      }
      .ls-health__error {
        border: 1px solid var(--danger-low-mid);
        background: var(--danger-low);
        color: var(--danger);
      }
      .ls-health__success {
        border: 1px solid var(--success-low-mid);
        background: var(--success-low);
        color: var(--success);
      }
      @media (max-width: 850px) {
        .ls-health__grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      @media (max-width: 700px) {
        .ls-health__hero { flex-direction: column; }
        .ls-health__actions { justify-content: flex-start; margin-left: 0; }
      }
      @media (max-width: 560px) {
        .ls-health__grid { grid-template-columns: 1fr; }
      }
    </style>

    <div class="ls-health">
      <section class="ls-health__hero">
        <div class="ls-health__copy">
          <h1>{{i18n "admin.link_safety.open_health"}}</h1>
          <p class="ls-health__muted">{{i18n "admin.link_safety.health_description"}}</p>
        </div>
        <div class="ls-health__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.link_safety.back_to_overview"}}</a>
          <a class="btn" href={{settingsUrl}}>{{i18n "admin.link_safety.open_settings"}}</a>
          <button class="btn" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.load}}>
            {{i18n "admin.link_safety.refresh"}}
          </button>
          <button class="btn btn-primary" type="button" disabled={{@controller.isTesting}} {{on "click" @controller.runTest}}>
            {{if @controller.isTesting (i18n "admin.link_safety.testing") (i18n "admin.link_safety.run_test")}}
          </button>
        </div>
      </section>

      {{#if @controller.error}}
        <div class="ls-health__error" role="alert">{{@controller.error}}</div>
      {{/if}}

      {{#if @controller.testResult}}
        <div class="ls-health__success" role="status">
          {{i18n "admin.link_safety.test_success"}}
        </div>
      {{/if}}

      {{#if @controller.data}}
        <section class="ls-health__panel">
          <h2>{{i18n "admin.link_safety.current_state"}}</h2>
          <div class="ls-health__grid">
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.status"}}</div>
              <div class="ls-health__value">{{if @controller.data.enabled (i18n "admin.link_safety.enabled") (i18n "admin.link_safety.disabled")}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.provider"}}</div>
              <div class="ls-health__value">{{@controller.data.provider_display}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.provider_configuration"}}</div>
              <div class="ls-health__value">{{if @controller.data.configured (i18n "admin.link_safety.configured") (i18n "admin.link_safety.not_configured")}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.mode"}}</div>
              <div class="ls-health__value">{{@controller.data.mode_display}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.circuit"}}</div>
              <div class="ls-health__value">{{if @controller.data.circuit_open (i18n "admin.link_safety.circuit_open") (i18n "admin.link_safety.circuit_closed")}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.cache_entries"}}</div>
              <div class="ls-health__value">{{@controller.data.valid_cache_entries}}</div>
            </div>
          </div>
        </section>

        <section class="ls-health__panel">
          <h2>{{i18n "admin.link_safety.provider_activity"}}</h2>
          <div class="ls-health__grid">
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.last_success"}}</div>
              <div class="ls-health__value">{{@controller.data.last_success_at_display}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.last_failure"}}</div>
              <div class="ls-health__value">{{@controller.data.last_failure_at_display}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.failure_code"}}</div>
              <div class="ls-health__value">{{@controller.data.last_failure_code_display}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.last_latency"}}</div>
              <div class="ls-health__value">{{if @controller.data.last_latency_ms @controller.data.last_latency_ms "-"}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.monthly_calls"}}</div>
              <div class="ls-health__value">{{@controller.data.provider_calls_month}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.circuit_open_until"}}</div>
              <div class="ls-health__value">{{@controller.data.circuit_open_until_display}}</div>
            </div>
          </div>
        </section>

        <section class="ls-health__panel">
          <h2>{{i18n "admin.link_safety.recent_activity"}}</h2>
          <div class="ls-health__grid">
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.detections_24h"}}</div>
              <div class="ls-health__value">{{@controller.data.detections_24h}}</div>
            </div>
            <div class="ls-health__item">
              <div class="ls-health__label">{{i18n "admin.link_safety.fail_open_24h"}}</div>
              <div class="ls-health__value">{{@controller.data.fail_open_24h}}</div>
            </div>
          </div>
        </section>
      {{else if @controller.isLoading}}
        <section class="ls-health__panel"><p>{{i18n "admin.link_safety.loading"}}</p></section>
      {{/if}}
    </div>
  </template>
);
