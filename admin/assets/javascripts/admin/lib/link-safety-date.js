import User from "discourse/models/user";
import { i18n } from "discourse-i18n";

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

  const timezone = userTimezone();
  const parsed = moment(value);
  if (!parsed.isValid()) {
    return value;
  }

  const local = parsed.tz(timezone);
  const formatted = local.format(i18n("dates.long_with_year"));
  const zone = local.format("z");

  return zone ? `${formatted} (${zone})` : formatted;
}

export function formatLinkSafetyDateOnly(value) {
  if (!value) {
    return "—";
  }

  const parsed = moment.utc(value, "YYYY-MM-DD", true);
  if (!parsed.isValid()) {
    return value;
  }

  return parsed.format(i18n("dates.medium.date_year"));
}
