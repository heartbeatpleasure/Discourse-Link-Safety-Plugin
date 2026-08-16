import "./api-initializers/link-safety-settings-button-fix";

export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("linkSafetyStatistics", { path: "/link-safety-statistics" });
  },
};
