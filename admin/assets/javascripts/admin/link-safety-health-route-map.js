export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("linkSafetyHealth", { path: "/link-safety-health" });
  },
};
