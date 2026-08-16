import { schedule } from "@ember/runloop";
import { apiInitializer } from "discourse/lib/api";

/**
 * Keep the Installed Plugins Settings control on the stable Link Safety
 * setting-key prefix. Current Discourse generates a plugin:<metadata-name>
 * filter for the generic Settings control; that filter can be empty for
 * mixed-case custom plugin names while the setting-key prefix is reliable.
 *
 * The primary admin route-map imports this initializer explicitly so it is
 * guaranteed to run in the admin application. The DOM observer and capture
 * click handler also cover older admin plugin-list renderers.
 */
export default apiInitializer("0.11.1", (api) => {
  const PLUGIN_DISPLAY_NAME = "Discourse-Link-Safety-Plugin";
  const FIXED_SETTINGS_URL =
    "/admin/site_settings/category/all_results?filter=link_safety";
  const SETTINGS_BUTTON_SELECTOR =
    `[data-plugin-setting-button="${PLUGIN_DISPLAY_NAME}"]`;

  let observer = null;
  let clickHandlerInstalled = false;

  function findPluginCards() {
    return Array.from(document.querySelectorAll("[data-plugin-name]")).concat(
      Array.from(
        document.querySelectorAll(
          ".admin-plugins-list .admin-plugin, .admin-plugin"
        )
      )
    );
  }

  function cardLooksLikeOurPlugin(card) {
    if (!card) {
      return false;
    }

    const dataName = card.getAttribute?.("data-plugin-name");
    if (
      dataName &&
      dataName.toLowerCase() === PLUGIN_DISPLAY_NAME.toLowerCase()
    ) {
      return true;
    }

    const text = (card.textContent || "").toLowerCase();
    if (text.includes(PLUGIN_DISPLAY_NAME.toLowerCase())) {
      return true;
    }

    return Boolean(
      card.querySelector?.('a[href*="Discourse-Link-Safety-Plugin"]')
    );
  }

  function rewriteSettingsLinkInCard(card) {
    if (!cardLooksLikeOurPlugin(card)) {
      return;
    }

    const anchors = Array.from(
      card.querySelectorAll('a[href*="/admin/site_settings"]')
    );

    for (const anchor of anchors) {
      if (anchor.dataset.linkSafetySettingsFixed === "1") {
        continue;
      }

      anchor.setAttribute("href", FIXED_SETTINGS_URL);
      anchor.dataset.linkSafetySettingsFixed = "1";
    }
  }

  function rewriteExactSettingsButtons() {
    const buttons = Array.from(
      document.querySelectorAll(SETTINGS_BUTTON_SELECTOR)
    );

    for (const button of buttons) {
      if (button.dataset.linkSafetySettingsFixed === "1") {
        continue;
      }

      button.setAttribute("href", FIXED_SETTINGS_URL);
      button.dataset.linkSafetySettingsFixed = "1";
    }
  }

  function rewriteAll() {
    schedule("afterRender", () => {
      rewriteExactSettingsButtons();
      findPluginCards().forEach((card) => rewriteSettingsLinkInCard(card));
    });
  }

  function installClickInterceptOnce() {
    if (clickHandlerInstalled) {
      return;
    }

    clickHandlerInstalled = true;

    document.addEventListener(
      "click",
      (event) => {
        if (!window.location?.pathname?.startsWith("/admin/plugins")) {
          return;
        }

        const target = event.target;
        if (!target) {
          return;
        }

        const exactControl = target.closest?.(SETTINGS_BUTTON_SELECTOR);
        if (exactControl) {
          event.preventDefault();
          event.stopPropagation();
          window.location.assign(FIXED_SETTINGS_URL);
          return;
        }

        const control =
          target.closest?.(
            'a[href*="/admin/site_settings"], button, .btn, .d-button'
          ) || target;
        const label = `${control.getAttribute?.("aria-label") || ""} ${
          control.getAttribute?.("title") || ""
        }`;
        const href = control.getAttribute?.("href") || "";
        const isSettingsControl =
          label.toLowerCase().includes("settings") ||
          href.includes("/admin/site_settings");

        if (!isSettingsControl) {
          return;
        }

        const card = control.closest?.("[data-plugin-name], .admin-plugin");
        if (!cardLooksLikeOurPlugin(card)) {
          return;
        }

        event.preventDefault();
        event.stopPropagation();
        window.location.assign(FIXED_SETTINGS_URL);
      },
      true
    );
  }

  function start() {
    rewriteAll();
    installClickInterceptOnce();

    observer?.disconnect();
    observer = new MutationObserver(() => rewriteAll());
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function stop() {
    observer?.disconnect();
    observer = null;
  }

  api.onPageChange((url) => {
    if (url?.startsWith("/admin/plugins")) {
      start();
    } else {
      stop();
    }
  });

  if (window.location?.pathname?.startsWith("/admin/plugins")) {
    start();
  }
});
