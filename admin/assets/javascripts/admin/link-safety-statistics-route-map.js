export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("linkSafetyStatistics", { path: "/link-safety-statistics" });
  },
};
