export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("linkSafety", { path: "/link-safety" });
  },
};
