import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const settingsUrl = getURL("/admin/site_settings/category/all_results?filter=link_safety");
const healthUrl = getURL("/admin/plugins/link-safety-health");
const detectionsUrl = getURL("/admin/plugins/link-safety-detections");
const statisticsUrl = getURL("/admin/plugins/link-safety-statistics");

export default RouteTemplate(<template>
  <div class="link-safety-admin">
    <section class="ls-admin__hero">
      <div><h1>{{i18n "admin.link_safety.title"}}</h1><p>{{i18n "admin.link_safety.description"}}</p></div>
      <a class="btn btn-primary" href={{settingsUrl}}>{{i18n "admin.link_safety.open_settings"}}</a>
    </section>
    <h2>{{i18n "admin.link_safety.overview_title"}}</h2>
    <section class="ls-admin__grid">
      <a class="ls-admin__card" href={{settingsUrl}}><h3>{{i18n "admin.link_safety.open_settings"}}</h3><p>{{i18n "admin.link_safety.settings_description"}}</p></a>
      <a class="ls-admin__card" href={{healthUrl}}><h3>{{i18n "admin.link_safety.open_health"}}</h3><p>{{i18n "admin.link_safety.health_description"}}</p></a>
      <a class="ls-admin__card" href={{detectionsUrl}}><h3>{{i18n "admin.link_safety.open_detections"}}</h3><p>{{i18n "admin.link_safety.detections_description"}}</p></a>
      <a class="ls-admin__card" href={{statisticsUrl}}><h3>{{i18n "admin.link_safety.open_statistics"}}</h3><p>{{i18n "admin.link_safety.statistics_description"}}</p></a>
    </section>
  </div>
</template>);
