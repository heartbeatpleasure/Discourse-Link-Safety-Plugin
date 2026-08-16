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
        --ls-surface-alt: var(--primary-very-low);
        --ls-border: var(--primary-low);
        --ls-muted: var(--primary-medium);
        display: flex;
        flex-direction: column;
        gap: 1rem;
        min-width: 0;
      }
      .ls-detections h1, .ls-detections h2, .ls-detections h3, .ls-detections p { margin: 0; }
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
      .ls-detections__list {
        display: flex;
        flex-direction: column;
        gap: .8rem;
        margin-top: .9rem;
      }
      .ls-detections__card {
        min-width: 0;
        padding: 1rem;
        border: 1px solid var(--ls-border);
        border-radius: 14px;
        background: var(--ls-surface-alt);
      }
      .ls-detections__card-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .ls-detections__identity {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .24rem;
      }
      .ls-detections__host {
        max-width: 100%;
        font-size: var(--font-up-1);
        line-height: 1.3;
        overflow-wrap: anywhere;
      }
      .ls-detections__user {
        display: inline-block;
        width: fit-content;
        max-width: 100%;
        color: var(--tertiary);
        font-weight: 600;
        line-height: 1.35;
        overflow-wrap: anywhere;
        text-decoration: none;
      }
      a.ls-detections__user:hover,
      a.ls-detections__user:focus-visible {
        text-decoration: underline;
      }
      .ls-detections__badges {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        justify-content: flex-end;
        gap: .4rem;
      }
      .ls-detections__badge {
        display: inline-flex;
        align-items: center;
        min-height: 28px;
        padding: .25rem .55rem;
        border: 1px solid var(--ls-border);
        border-radius: 999px;
        background: var(--secondary);
        font-size: var(--font-down-1);
        font-weight: 700;
        white-space: nowrap;
      }
      .ls-detections__meta {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .6rem;
        margin-top: .85rem;
      }
      .ls-detections__meta-item {
        min-width: 0;
        padding: .65rem .7rem;
        border-radius: 10px;
        background: var(--secondary);
      }
      .ls-detections__meta-label {
        color: var(--ls-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .ls-detections__meta-value {
        margin-top: .18rem;
        font-weight: 600;
        overflow-wrap: anywhere;
      }
      .ls-detections__date { white-space: nowrap; }
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
        background: var(--ls-surface-alt);
        color: var(--ls-muted);
      }
      @media (max-width: 900px) {
        .ls-detections__meta { grid-template-columns: 1fr 1fr; }
      }
      @media (max-width: 700px) {
        .ls-detections__hero,
        .ls-detections__card-header { flex-direction: column; align-items: stretch; }
        .ls-detections__actions { justify-content: flex-start; margin-left: 0; }
        .ls-detections__badges { justify-content: flex-start; }
        .ls-detections__meta { grid-template-columns: 1fr; }
        .ls-detections__date { white-space: normal; }
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
          <div class="ls-detections__list">
            {{#each @controller.data.detections as |row|}}
              <article class="ls-detections__card">
                <div class="ls-detections__card-header">
                  <div class="ls-detections__identity">
                    <h3 class="ls-detections__host">{{row.host}}</h3>
                    {{#if row.user_url}}
                      <a class="ls-detections__user" href={{row.user_url}}>{{row.username}}</a>
                    {{else}}
                      <span class="ls-detections__muted">{{i18n "admin.link_safety.user_unavailable"}}</span>
                    {{/if}}
                  </div>
                  <div class="ls-detections__badges">
                    {{#each row.threats_display as |threat|}}
                      <span class="ls-detections__badge">{{threat}}</span>
                    {{/each}}
                    <span class="ls-detections__badge">{{row.action_display}}</span>
                  </div>
                </div>

                <div class="ls-detections__meta">
                  <div class="ls-detections__meta-item">
                    <div class="ls-detections__meta-label">{{i18n "admin.link_safety.date"}}</div>
                    <div class="ls-detections__meta-value ls-detections__date">{{row.detected_at_display}}</div>
                  </div>
                  <div class="ls-detections__meta-item">
                    <div class="ls-detections__meta-label">{{i18n "admin.link_safety.surface"}}</div>
                    <div class="ls-detections__meta-value">{{row.surface_display}}</div>
                  </div>
                  <div class="ls-detections__meta-item">
                    <div class="ls-detections__meta-label">{{i18n "admin.link_safety.provider"}}</div>
                    <div class="ls-detections__meta-value">{{row.provider_display}}</div>
                  </div>
                </div>
              </article>
            {{/each}}
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
