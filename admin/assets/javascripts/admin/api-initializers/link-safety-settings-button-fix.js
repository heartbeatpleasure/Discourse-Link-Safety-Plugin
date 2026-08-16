import { schedule } from "@ember/runloop";
import { apiInitializer } from "discourse/lib/api";

/**
 * Keep the Installed Plugins Settings control for Link Safety on the reliable
 * setting-key prefix. Some Discourse builds generate a plugin-name filter that
 * can render an empty settings result even though the settings themselves are
 * registered correctly.
 */
export default apiInitializer("0.11.1", (api) => {
  const PLUGIN_DISPLAY_NAME = "Discourse-Link-Safety-Plugin";
  const FIXED_SETTINGS_URL =
    "/admin/site_settings/category/all_results?filter=link_safety";

  let observer = null;
  let clickHandlerInstalled = false;

  function findPluginCards() {
    return Array.from(document.querySelectorAll("[data-plugin-name]")).concat(
      Array.from(
        document.querySelectorAll(
          ".admin-plugins-list .admin-plugin, .admin-plugin",
        ),
      ),
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
      card.querySelector?.('a[href*="Discourse-Link-Safety-Plugin"]'),
    );
  }

  function rewriteSettingsLinkInCard(card) {
    if (!cardLooksLikeOurPlugin(card)) {
      return;
    }

    const anchors = Array.from(
      card.querySelectorAll('a[href*="/admin/site_settings"]'),
    );

    for (const anchor of anchors) {
      if (anchor.dataset.linkSafetySettingsFixed === "1") {
        continue;
      }

      anchor.setAttribute("href", FIXED_SETTINGS_URL);
      anchor.dataset.linkSafetySettingsFixed = "1";
    }
  }

  function rewriteAll() {
    schedule("afterRender", () => {
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

        const control =
          target.closest?.(
            'a[href*="/admin/site_settings"], button, .btn, .d-button',
          ) || target;

        const label = `${control.getAttribute?.("aria-label") || ""} ${
          control.getAttribute?.("title") || ""
        }`;
        const href = control.getAttribute?.("href") || "";
        const settingsControl =
          label.toLowerCase().includes("settings") ||
          href.includes("/admin/site_settings");

        if (!settingsControl) {
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
      true,
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
