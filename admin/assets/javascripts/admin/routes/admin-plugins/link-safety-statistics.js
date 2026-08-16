import DiscourseRoute from "discourse/routes/discourse";
import { i18n } from "discourse-i18n";
export default class AdminPluginsLinkSafetyStatisticsRoute extends DiscourseRoute {
  titleToken() { return i18n("admin.link_safety.open_statistics"); }
  setupController(controller) { super.setupController(...arguments); controller.load?.(); }
}
