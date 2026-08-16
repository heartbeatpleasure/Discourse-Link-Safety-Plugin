import { i18n } from "discourse-i18n";

function humanizeToken(value) {
  const text = value?.toString().trim();
  if (!text) {
    return "—";
  }

  const normalized = text.replace(/[_-]+/g, " ").toLowerCase();
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

export function providerLabel(provider) {
  switch (provider) {
    case "safe_browsing_v5":
      return i18n("admin.link_safety.provider_safe_browsing_v5");
    case "web_risk_lookup":
      return i18n("admin.link_safety.provider_web_risk");
    case "urlhaus":
      return "URLhaus";
    default:
      return humanizeToken(provider);
  }
}

export function modeLabel(mode) {
  const key = {
    monitor: "mode_monitor",
    enforce: "mode_enforce",
  }[mode];

  return key ? i18n(`admin.link_safety.${key}`) : humanizeToken(mode);
}

export function surfaceLabel(surface) {
  const key = {
    public_post: "surface_public_post",
    private_message: "surface_private_message",
    chat_public: "surface_chat_public",
    chat_dm: "surface_chat_dm",
    profile: "surface_profile",
  }[surface];

  return key ? i18n(`admin.link_safety.${key}`) : humanizeToken(surface);
}

export function actionLabel(action) {
  const key = {
    monitor_only: "action_monitor_only",
    blocked_before_save: "action_blocked_before_save",
    disabled_after_publish: "action_disabled_after_publish",
  }[action];

  return key ? i18n(`admin.link_safety.${key}`) : humanizeToken(action);
}

export function threatLabel(threat) {
  const key = {
    MALWARE: "threat_malware",
    SOCIAL_ENGINEERING: "threat_social_engineering",
    UNWANTED_SOFTWARE: "threat_unwanted_software",
    POTENTIALLY_HARMFUL_APPLICATION: "threat_potentially_harmful_application",
  }[threat];

  return key ? i18n(`admin.link_safety.${key}`) : humanizeToken(threat);
}

export function failureCodeLabel(code) {
  return humanizeToken(code);
}
