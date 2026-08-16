import { ajax } from "discourse/lib/ajax";
import DiscourseRoute from "discourse/routes/discourse";
import { i18n } from "discourse-i18n";

export default class AdminPluginsLinkSafetyRoute extends DiscourseRoute {
  model() {
    return ajax("/admin/plugins/link-safety/overview.json");
  }

  titleToken() {
    return i18n("admin.link_safety.title");
  }
}
