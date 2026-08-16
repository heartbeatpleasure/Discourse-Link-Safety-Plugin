import "./api-initializers/link-safety-settings-button-fix";

export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("linkSafetyHealth", { path: "/link-safety-health" });
  },
};
