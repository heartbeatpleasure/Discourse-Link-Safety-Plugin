export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("linkSafetyDetections", { path: "/link-safety-detections" });
  },
};
