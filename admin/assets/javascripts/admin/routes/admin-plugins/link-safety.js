import { ajax } from "discourse/lib/ajax";
import DiscourseRoute from "discourse/routes/discourse";
import { i18n } from "discourse-i18n";
import { modeLabel, providerLabel } from "../../lib/link-safety-display";

export default class AdminPluginsLinkSafetyRoute extends DiscourseRoute {
  async model() {
    const data = await ajax("/admin/plugins/link-safety/overview.json");
    return {
      ...data,
      provider_display: providerLabel(data.provider),
      mode_display: modeLabel(data.mode),
    };
  }

  titleToken() {
    return i18n("admin.link_safety.title");
  }
}
