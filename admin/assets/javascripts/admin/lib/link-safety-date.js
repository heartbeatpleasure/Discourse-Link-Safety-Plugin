import User from "discourse/models/user";

function browserLocales() {
  const languages = globalThis.navigator?.languages;
  if (Array.isArray(languages) && languages.length > 0) {
    return languages;
  }

  const language = globalThis.navigator?.language;
  if (language) {
    return [language];
  }

  const effectiveLocale = User.current()?.effective_locale;
  return effectiveLocale ? [effectiveLocale.replace(/_/g, "-")] : undefined;
}

function browserHourCycle() {
  try {
    return new Intl.DateTimeFormat(undefined, { hour: "numeric" }).resolvedOptions()
      .hourCycle;
  } catch {
    return undefined;
  }
}

function userTimezone() {
  const configuredTimezone = User.current()?.user_option?.timezone;
  if (configuredTimezone && moment.tz.zone(configuredTimezone)) {
    return configuredTimezone;
  }

  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || moment.tz.guess();
  } catch {
    return moment.tz.guess();
  }
}

export function formatLinkSafetyDateTime(value) {
  if (!value) {
    return "—";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  const timezone = userTimezone();

  try {
    return new Intl.DateTimeFormat(browserLocales(), {
      timeZone: timezone,
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: browserHourCycle(),
      timeZoneName: "short",
    }).format(parsed);
  } catch {
    const fallback = moment(value);
    if (!fallback.isValid()) {
      return value;
    }

    return fallback.tz(timezone).format("D MMM YYYY, HH:mm z");
  }
}

export function formatLinkSafetyDateOnly(value, { month = "long" } = {}) {
  if (!value) {
    return "—";
  }

  const match = String(value).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) {
    return value;
  }

  const [, year, monthNumber, day] = match;
  const parsed = new Date(
    Date.UTC(Number(year), Number(monthNumber) - 1, Number(day), 12, 0, 0)
  );

  try {
    return new Intl.DateTimeFormat(browserLocales(), {
      timeZone: "UTC",
      year: "numeric",
      month,
      day: "numeric",
    }).format(parsed);
  } catch {
    const fallbackFormat = month === "long" ? "D MMMM YYYY" : "D MMM YYYY";
    return moment.utc(value, "YYYY-MM-DD", true).format(fallbackFormat);
  }
}
