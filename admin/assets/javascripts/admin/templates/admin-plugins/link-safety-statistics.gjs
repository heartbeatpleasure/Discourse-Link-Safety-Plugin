import RouteTemplate from "ember-route-template";
import { on } from "@ember/modifier";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";
const backUrl = getURL("/admin/plugins/link-safety");
export default RouteTemplate(<template>
  <div class="link-safety-admin"><section class="ls-admin__hero"><div><h1>{{i18n "admin.link_safety.open_statistics"}}</h1><p>{{i18n "admin.link_safety.statistics_description"}}</p></div><div class="ls-admin__actions"><select {{on "change" @controller.setDays}}><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option><option value="365">365 days</option></select><button class="btn" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.load}}>{{i18n "admin.link_safety.refresh"}}</button><a class="btn" href={{backUrl}}>{{i18n "admin.link_safety.back_to_overview"}}</a></div></section>
  {{#if @controller.error}}<div class="ls-admin__error">{{@controller.error}}</div>{{/if}}
  {{#if @controller.data.rows.length}}<div class="ls-admin__table-wrap"><table class="table"><thead><tr><th>{{i18n "admin.link_safety.date"}}</th><th>{{i18n "admin.link_safety.provider"}}</th><th>{{i18n "admin.link_safety.checks"}}</th><th>{{i18n "admin.link_safety.provider_calls"}}</th><th>{{i18n "admin.link_safety.cache_hits"}}</th><th>{{i18n "admin.link_safety.threat_count"}}</th><th>{{i18n "admin.link_safety.errors"}}</th><th>{{i18n "admin.link_safety.fail_open"}}</th></tr></thead><tbody>{{#each @controller.data.rows as |row|}}<tr><td>{{row.date}}</td><td>{{row.provider}}</td><td>{{row.checks}}</td><td>{{row.provider_calls}}</td><td>{{row.cache_hits}}</td><td>{{row.threats}}</td><td>{{row.errors}}</td><td>{{row.fail_open}}</td></tr>{{/each}}</tbody></table></div>{{else if @controller.data}}<p>{{i18n "admin.link_safety.no_data"}}</p>{{/if}}</div>
</template>);
