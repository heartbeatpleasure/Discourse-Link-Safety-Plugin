// Compatibility shim for older Link Safety route-map imports.
//
// The active initializer now lives in the standard Discourse plugin location:
// assets/javascripts/discourse/api-initializers/link-safety-settings-button-fix.js
// and is auto-loaded by Discourse. Keeping this module harmless avoids a second
// observer/click handler on installations that still have a cached route map.
export {};
