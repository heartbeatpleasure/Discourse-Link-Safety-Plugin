import { apiInitializer } from "discourse/lib/api";

// Compatibility no-op for installations upgraded from Link Safety v1.0.1.
// The active Settings-button fix lives in the admin application and is loaded
// explicitly by admin/link-safety-route-map.js. This file remains intentionally
// behavior-free, but must still expose a valid initializer because Discourse
// auto-discovers modules in discourse/api-initializers.
export default apiInitializer(() => {});
