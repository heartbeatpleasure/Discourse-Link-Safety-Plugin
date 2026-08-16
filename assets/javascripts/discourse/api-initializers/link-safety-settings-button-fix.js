// Compatibility no-op for v1.0.1 installations.
//
// The active Settings-button initializer belongs to the admin application and
// is loaded explicitly from admin/link-safety-route-map.js. Keeping this file
// harmless prevents duplicate observers/click handlers when v1.0.2 is copied
// over an existing v1.0.1 plugin directory.
export {};
