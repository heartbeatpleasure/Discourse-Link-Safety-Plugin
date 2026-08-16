# Discourse Link Safety Plugin

Server-side malicious-link protection for Discourse posts, private messages, Chat messages, oneboxes, and profile links.

## Repository name

`Discourse-Link-Safety-Plugin`

## Providers

The plugin supports two primary provider modes:

- `safe_browsing_v5` - Google Safe Browsing v5 hash-prefix lookup. Intended only for deployments that satisfy Google's non-commercial usage requirement. Requires a Google API key and the explicit non-commercial acknowledgement setting.
- `web_risk_lookup` - Google Web Risk Lookup API for commercial/revenue-generating deployments. Requires a Google Cloud project, Web Risk API enablement, billing-enabled project, and an API key permitted to call Web Risk.

URLhaus is an optional supplemental malware-distribution source. It is disabled by default and requires an abuse.ch Auth-Key when enabled.

## Installation

Add the plugin to the Discourse container configuration in the normal way and rebuild. The plugin setting `link_safety_enabled` defaults to `false`, so installation does not immediately make provider calls or change posting behavior.

## Initial configuration

1. Keep `link_safety_enabled = false` during the first rebuild and health check.
2. Select the appropriate primary provider.
3. Configure `link_safety_google_api_key`.
4. If Safe Browsing is selected, enable `link_safety_safe_browsing_noncommercial_acknowledged` only when the deployment is actually eligible.
5. Before using either Google provider, make Google's required user-protection notice visible to users (for example in the site's accepted Terms/Community Guidelines). This is an operator/documentation obligation and does not gate runtime provider operation.
6. Leave URLhaus disabled initially unless its supplemental check is required.
7. Start with `link_safety_mode = monitor`.
8. Enable `link_safety_enabled` and run the provider test from Admin > Plugins > Link Safety > Health.
9. Verify clean and known-test URL behavior on staging before changing to `link_safety_mode = enforce`.

## Covered surfaces

- Public topics and replies
- Private-message topics and replies
- Public/restricted Chat channels
- Chat direct-message channels
- Chat message edits
- Full and inline onebox source links
- Profile website and biography links when changed

Internal Discourse links are skipped. Only HTTP(S) navigation targets are reputation checked. The plugin does not replace Discourse upload/file scanning or onebox SSRF protections.

## Trusted domains

`link_safety_trusted_domains` is a Discourse list setting. Enter hostnames only. When `link_safety_trusted_domains_include_subdomains` is disabled (default), only exact hosts are trusted. Do not globally trust URL shorteners, shared cloud-storage domains, paste services, or broad user-generated-content platforms.

## Failure policy

Default: `fail_open`.

Transient provider availability failures can follow the configured `fail_open` policy. Security-control integrity failures such as canonicalization failures, malformed provider responses, exhausted validation budgets, or provider authentication/request-contract failures are rejected in Enforce mode even when transient provider outages are configured fail-open. `fail_closed` remains available for environments that require every uncached external link to receive a provider verdict.

## Privacy

- Safe Browsing v5 mode sends 4-byte SHA-256 hash prefixes rather than the full URL.
- Web Risk Lookup sends the full checked URL to Google. Private-message and direct-chat URLs are therefore not sent to Web Risk unless `link_safety_web_risk_private_surfaces` is explicitly enabled.
- URLhaus receives the full URL and is disabled for private surfaces by default.
- Full-URL providers do not receive loopback, private, link-local, reserved, or intranet destinations unless `link_safety_full_url_providers_allow_private_networks` is explicitly enabled.
- Plugin cache/detection/statistics tables do not store full URLs. New URL identifiers use a site-secret HMAC-SHA-256 fingerprint plus the normalized hostname. Existing SHA-256 cache identifiers are accepted only as a temporary read fallback until their normal cache expiry, preventing protection gaps during upgrade.
- Google API keys are sent in the `X-Goog-Api-Key` request header instead of the request URL, and all API/Auth keys remain secret server-side site settings.

## Operational hardening

- Provider responses are streamed into a bounded buffer and rejected once they exceed 512 KiB; a declared oversized `Content-Length` is rejected before body reads.
- HTTPS provider connections verify certificates and require TLS 1.2 or newer when supported by the running Ruby/OpenSSL stack.
- A single validation deadline is shared by primary and supplemental provider work for one check operation.
- Uncached remote lookup work is protected by both a weighted per-user 10-minute budget and a global per-minute budget, independent of Discourse's normal posting rate limits. This limits API-cost abuse and resource exhaustion.
- An absolute 200-candidate ceiling is enforced before canonicalization so malformed/high-volume URL submissions cannot force unbounded parsing work.
- Pending retries re-check the current surface settings and current Monitor/Enforce mode before doing provider work.
- The Health page exposes privacy-safe internal security-control failure counters that expire after one hour without another failure; no URLs, message content, API keys, or provider response bodies are included. Repeated/internal control failures also surface through the Discourse problem-check framework.
- Cached verdicts retain the provider that actually supplied the verdict, including URLhaus supplemental detections.

## User Notes

If the bundled Discourse User Notes plugin is enabled, Link Safety can add a staff note after repeated confirmed threat events. Default mode is `threshold_only`. Monitor-only detections do not create notes.

## Automated tests

The plugin includes specs for Safe Browsing canonicalization/expression generation, monitor/enforce behavior, fail-open/fail-closed behavior, threat rendering, and onebox gating. External providers must be stubbed in automated test suites; live API calls belong only in explicit staging/Health tests.

## Recommended rollout

1. Rebuild with plugin disabled.
2. Configure provider and key.
3. Run Health provider test.
4. Enable plugin in Monitor mode.
5. Test public topic, PM, Chat, Chat DM, profile link, ordinary link, bare link, and onebox cases.
6. Review Detections/Statistics/Health.
7. Switch to Enforce only after staging behavior is verified.

## Post-rebuild staging smoke test

Run the first rebuild with `link_safety_enabled = false`, then use this sequence on staging:

1. Open **Admin > Plugins > Link Safety** and verify that **Settings**, **Health**, **Detections**, and **Statistics** all open without console errors. The Installed Plugins **Settings** control should open the filtered `link_safety` settings page.
2. Configure the primary provider and API key, keep `link_safety_mode = monitor`, enable `link_safety_enabled`, then run **Health > Run provider test**.
3. Post a normal external link in a public topic, a private message, a public Chat channel, and a Chat direct message. Repeat with a bare URL and a URL that normally renders as a onebox. All should continue to work in monitor mode.
4. Change a profile website/bio to contain a normal external link and confirm that it saves.
5. On staging only, use Google's documented malware test URL `http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/`. In monitor mode the content should remain publishable while a detection is recorded.
6. Change to `link_safety_mode = enforce` and repeat the malware test URL in a public post, PM, Chat, Chat DM, and profile field. The create/edit should be rejected; existing content must remain unchanged when an edit is rejected.
7. Add `example.com` to `link_safety_trusted_domains` and verify that a link to that exact host bypasses provider lookup. Keep `link_safety_trusted_domains_include_subdomains = false` unless subdomain trust is intentionally required.
8. Temporarily simulate a transient provider timeout on staging if you need to verify `fail_open`; authentication/configuration errors such as an invalid API key are intentionally treated as hard verification failures in Enforce mode. Profile link changes remain fail-closed by default. Restore normal provider operation immediately after the test.
9. Verify that existing oneboxes, normal internal Discourse links, uploads, mentions, hashtags, code blocks containing URL text, and ordinary posting/chat behavior are unchanged.
10. Review **Detections**, **Statistics**, and **Health**, then switch from monitor to enforce only after the staging results are correct.

The malware URL above is a provider-owned test fixture; do not replace it with a live malicious site.

## Provider selection and required credentials

- **Google Safe Browsing v5**: intended only for eligible non-commercial use. Enable the Safe Browsing API in a Google Cloud project, create a server-side API key, configure `link_safety_google_api_key`, and enable `link_safety_safe_browsing_noncommercial_acknowledged` only when the deployment qualifies. Safe Browsing itself is free; Google assigns a project-specific quota visible in the Developer Console.
- **Google Web Risk Lookup**: use this for commercial or revenue-generating deployments. Enable Web Risk in Google Cloud and configure the same Google API key setting. The first 100,000 Lookup calls per month are free; subsequent calls are billed by Google.
- **URLhaus**: optional supplemental malware-distribution source. It requires a free abuse.ch Auth-Key. It is disabled by default and private-message/direct-chat URLs are not sent to URLhaus unless explicitly enabled.

The plugin defaults to **disabled** and **monitor** mode. Configure and test the provider first, enable the plugin in monitor mode, then switch to enforce mode after verifying normal traffic.

## Google provider user protection and attribution

Before using either Google provider, the site operator must make a user-protection notice visible to users before they use Link Safety. The notice must explain that Google-based protection can produce both false positives and false negatives. This documentation/Terms obligation is deliberately not implemented as a runtime Site Setting gate: provider operation depends on the actual provider credentials and, for Safe Browsing v5, the separate non-commercial eligibility acknowledgement. Google suggests language equivalent to: Google works to provide accurate and up-to-date information about unsafe web resources, but cannot guarantee that its information is comprehensive and error-free; some risky sites may not be identified and some safe sites may be identified in error.

When a warning is based on a Google verdict, Link Safety includes Google attribution and an advisory reference. URLhaus-only warnings deliberately do not include Google attribution. Safe Browsing threat verdicts are never enforced beyond 30 minutes without fresh Google data. Web Risk threat verdicts require and respect the provider's valid `expireTime`; missing, malformed, or expired positive-cache timestamps are treated as provider errors. Empty Web Risk Lookup responses are not negatively cached because Lookup does not define a negative-cache lifetime.

## Settings navigation

The plugin is available under **Admin > Plugins > Link Safety**. The Settings button opens the filtered Discourse Site Settings view for `link_safety`, matching the normal Installed Plugins workflow.
