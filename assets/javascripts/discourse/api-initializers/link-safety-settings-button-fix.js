import { schedule } from "@ember/runloop";
import getURL from "discourse/lib/get-url";
import { apiInitializer } from "discourse/lib/api";

/**
 * Discourse currently builds the Installed Plugins settings link from the
 * plugin metadata name (`plugin:<name>`). Plugin site-settings are associated
 * with the plugin directory name, and that token can be case-sensitive in the
 * settings filter. Keep this plugin's Settings control on the stable
 * `link_safety` setting-key prefix instead.
 */
export default apiInitializer("0.11.1", (api) => {
  const PLUGIN_DISPLAY_NAME = "Discourse-Link-Safety-Plugin";
  const SETTINGS_URL = getURL(
    "/admin/site_settings/category/all_results?filter=link_safety",
  );
  const SETTINGS_BUTTON_SELECTOR =
    `[data-plugin-setting-button="${PLUGIN_DISPLAY_NAME}"]`;
  const PLUGIN_ROW_SELECTOR = `[data-plugin-name="${PLUGIN_DISPLAY_NAME}"]`;

  let observer = null;
  let clickHandlerInstalled = false;

  function onInstalledPluginsPage() {
    return window.location?.pathname?.includes("/admin/plugins");
  }

  function settingsControls() {
    const direct = Array.from(
      document.querySelectorAll(SETTINGS_BUTTON_SELECTOR),
    );

    if (direct.length) {
      return direct;
    }

    const row = document.querySelector(PLUGIN_ROW_SELECTOR);
    if (!row) {
      return [];
    }

    return Array.from(row.querySelectorAll('a[href*="/admin/site_settings"]'));
  }

  function rewriteSettingsLinks() {
    if (!onInstalledPluginsPage()) {
      return;
    }

    schedule("afterRender", () => {
      settingsControls().forEach((control) => {
        if (control.dataset.linkSafetySettingsFixed === "1") {
          return;
        }

        control.setAttribute("href", SETTINGS_URL);
        control.dataset.linkSafetySettingsFixed = "1";
      });
    });
  }

  function installClickHandler() {
    if (clickHandlerInstalled) {
      return;
    }

    clickHandlerInstalled = true;

    document.addEventListener(
      "click",
      (event) => {
        if (!onInstalledPluginsPage()) {
          return;
        }

        const target = event.target;
        if (!(target instanceof Element)) {
          return;
        }

        let control = target.closest(SETTINGS_BUTTON_SELECTOR);

        if (!control) {
          const row = target.closest(PLUGIN_ROW_SELECTOR);
          const possibleControl = target.closest(
            'a[href*="/admin/site_settings"], button, .btn, .d-button',
          );
          if (row && possibleControl) {
            const label = `${possibleControl.getAttribute("aria-label") || ""} ${possibleControl.getAttribute("title") || ""}`;
            const href = possibleControl.getAttribute("href") || "";
            if (
              label.toLowerCase().includes("settings") ||
              href.includes("/admin/site_settings")
            ) {
              control = possibleControl;
            }
          }
        }

        if (!control) {
          return;
        }

        event.preventDefault();
        event.stopImmediatePropagation();
        window.location.assign(SETTINGS_URL);
      },
      true,
    );
  }

  function start() {
    rewriteSettingsLinks();
    installClickHandler();

    observer?.disconnect();
    observer = new MutationObserver(rewriteSettingsLinks);
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function stop() {
    observer?.disconnect();
    observer = null;
  }

  api.onPageChange(() => {
    if (onInstalledPluginsPage()) {
      start();
    } else {
      stop();
    }
  });

  if (onInstalledPluginsPage()) {
    start();
  }
});
