import RouteTemplate from "ember-route-template";
import { on } from "@ember/modifier";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";
const backUrl = getURL("/admin/plugins/link-safety");
const settingsUrl = getURL("/admin/site_settings/category/all_results?filter=link_safety");
export default RouteTemplate(<template>
  <div class="link-safety-admin">
    <section class="ls-admin__hero"><div><h1>{{i18n "admin.link_safety.open_health"}}</h1><p>{{i18n "admin.link_safety.health_description"}}</p></div><div class="ls-admin__actions"><button class="btn" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.load}}>{{i18n "admin.link_safety.refresh"}}</button><button class="btn btn-primary" type="button" disabled={{@controller.isTesting}} {{on "click" @controller.runTest}}>{{if @controller.isTesting (i18n "admin.link_safety.testing") (i18n "admin.link_safety.run_test")}}</button><a class="btn" href={{settingsUrl}}>{{i18n "admin.link_safety.open_settings"}}</a><a class="btn" href={{backUrl}}>{{i18n "admin.link_safety.back_to_overview"}}</a></div></section>
    {{#if @controller.error}}<div class="ls-admin__error">{{@controller.error}}</div>{{/if}}
    {{#if @controller.data}}<section class="ls-admin__metrics">
      <div><span>{{i18n "admin.link_safety.status"}}</span><strong>{{if @controller.data.enabled (i18n "admin.link_safety.enabled") (i18n "admin.link_safety.disabled")}}</strong></div>
      <div><span>{{i18n "admin.link_safety.provider"}}</span><strong>{{@controller.data.provider}}</strong></div>
      <div><span>{{i18n "admin.link_safety.mode"}}</span><strong>{{@controller.data.mode}}</strong></div>
      <div><span>{{i18n "admin.link_safety.circuit"}}</span><strong>{{if @controller.data.circuit_open "Open" "Closed"}}</strong></div>
      <div><span>{{i18n "admin.link_safety.cache_entries"}}</span><strong>{{@controller.data.valid_cache_entries}}</strong></div>
      <div><span>{{i18n "admin.link_safety.monthly_calls"}}</span><strong>{{@controller.data.provider_calls_month}}</strong></div>
      <div><span>{{i18n "admin.link_safety.detections_24h"}}</span><strong>{{@controller.data.detections_24h}}</strong></div>
      <div><span>{{i18n "admin.link_safety.fail_open_24h"}}</span><strong>{{@controller.data.fail_open_24h}}</strong></div>
    </section>{{else if @controller.isLoading}}<p>{{i18n "admin.link_safety.loading"}}</p>{{/if}}
  </div>
</template>);
