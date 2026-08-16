import RouteTemplate from "ember-route-template";
import { on } from "@ember/modifier";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";
const backUrl = getURL("/admin/plugins/link-safety");
export default RouteTemplate(<template>
  <div class="link-safety-admin"><section class="ls-admin__hero"><div><h1>{{i18n "admin.link_safety.open_detections"}}</h1><p>{{i18n "admin.link_safety.detections_description"}}</p></div><div class="ls-admin__actions"><button class="btn" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.load}}>{{i18n "admin.link_safety.refresh"}}</button><a class="btn" href={{backUrl}}>{{i18n "admin.link_safety.back_to_overview"}}</a></div></section>
  {{#if @controller.error}}<div class="ls-admin__error">{{@controller.error}}</div>{{/if}}
  {{#if @controller.data.detections.length}}<div class="ls-admin__table-wrap"><table class="table"><thead><tr><th>{{i18n "admin.link_safety.date"}}</th><th>{{i18n "admin.link_safety.host"}}</th><th>{{i18n "admin.link_safety.threats"}}</th><th>{{i18n "admin.link_safety.surface"}}</th><th>{{i18n "admin.link_safety.action"}}</th><th>{{i18n "admin.link_safety.username"}}</th></tr></thead><tbody>{{#each @controller.data.detections as |row|}}<tr><td>{{row.detected_at}}</td><td>{{row.host}}</td><td>{{row.threat_types}}</td><td>{{row.surface}}</td><td>{{row.action}}</td><td>{{row.username}}</td></tr>{{/each}}</tbody></table></div>{{else if @controller.data}}<p>{{i18n "admin.link_safety.no_detections"}}</p>{{/if}}</div>
</template>);
