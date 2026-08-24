# Discourse Link Safety Plugin

Server-side malicious-link protection for Discourse posts, private messages, Chat messages, oneboxes, profile links, topic featured links, and group biographies.

## Repository name

`Discourse-Link-Safety-Plugin`

## Providers

The plugin supports two primary provider modes:

- `safe_browsing_v5` - Google Safe Browsing v5 hash-prefix lookup. Intended only for deployments that satisfy Google's non-commercial usage requirement. Requires a Google API key and the explicit non-commercial acknowledgement setting.
- `web_risk_lookup` - Google Web Risk Lookup API for commercial/revenue-generating deployments. Requires a Google Cloud project, Web Risk API enablement, billing-enabled project, and an API key permitted to call Web Risk.

URLhaus is an optional supplemental malware-distribution source. It is disabled by default and requires an abuse.ch Auth-Key when enabled. Operators are responsible for ensuring their usage complies with the current URLhaus API/fair-use and commercial-use terms.

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
- Topic featured links when created or changed (optional; disabled by default on upgrade)
- Non-automatic group biography links when changed (optional; disabled by default on upgrade)

Discourse-generated browser-relative links (including mentions, group mentions, hashtags, quotes, Chat transcript links, and other current/future relative routes) are skipped before Safe Browsing canonicalization. Absolute links to the current Discourse origin are also skipped. Uploads and attachments are recognized through the active Discourse `FileStore`, including site-owned S3/CDN paths, without hardcoding a forum or storage hostname. Only external HTTP(S) navigation targets are reputation checked. The plugin does not replace Discourse upload/file scanning or onebox SSRF protections.

## Trusted domains

`link_safety_trusted_domains` is a Discourse list setting. Enter hostnames only. When `link_safety_trusted_domains_include_subdomains` is disabled (default), only exact hosts are trusted. Do not globally trust URL shorteners, shared cloud-storage domains, paste services, or broad user-generated-content platforms.

## Failure policy

Default: `fail_open`.

Transient provider availability failures can follow the configured `fail_open` policy. Security-control integrity failures such as canonicalization failures, malformed provider responses, exhausted validation budgets, or provider authentication/request-contract failures are rejected in Enforce mode even when transient provider outages are configured fail-open. `fail_closed` remains available for environments that require every uncached external link to receive a provider verdict.

## Privacy

- Safe Browsing v5 mode sends 4-byte SHA-256 hash prefixes rather than the full URL.
- Web Risk Lookup sends the full checked URL to Google. Privacy-sensitive content—including private messages, whispers, read-restricted categories/Chat, hidden or otherwise anonymously restricted profiles, non-public group biographies, restricted featured links, and login-required sites—is therefore not sent to Web Risk unless `link_safety_web_risk_private_surfaces` is explicitly enabled.
- URLhaus also receives the full URL and follows the same privacy-context separation through its own `link_safety_urlhaus_private_surfaces` opt-in. Functional surface labels remain unchanged; privacy is evaluated independently.
- Full-URL providers do not receive loopback, private, link-local, reserved, or intranet destinations unless `link_safety_full_url_providers_allow_private_networks` is explicitly enabled.
- Plugin cache/detection/statistics tables do not store full URLs. New URL identifiers use a site-secret HMAC-SHA-256 fingerprint plus the normalized hostname. Existing SHA-256 cache identifiers are accepted only as a temporary read fallback until their normal cache expiry, preventing protection gaps during upgrade.
- Google API keys are sent in the `X-Goog-Api-Key` request header instead of the request URL, and all API/Auth keys remain secret server-side site settings.

## Operational hardening

- Provider responses are streamed into a bounded buffer and rejected once they exceed 512 KiB; a declared oversized `Content-Length` is rejected before body reads.
- HTTPS provider connections verify certificates and require TLS 1.2 or newer when supported by the running Ruby/OpenSSL stack.
- A single validation deadline is shared by primary and supplemental provider work for one check operation.
- Uncached remote lookup work is protected by both a weighted per-user 10-minute budget and a global per-minute budget, independent of Discourse's normal posting rate limits. A configurable portion of the global budget is reserved for staff actions, retries, final-cooked verification, and periodic revalidation, so ordinary traffic cannot starve already-published-content remediation.
- An absolute 200-candidate ceiling is enforced before canonicalization so malformed/high-volume URL submissions cannot force unbounded parsing work.
- Pending retries re-check the current surface settings and current Monitor/Enforce mode before doing provider work.
- Pending post/Chat retries carry a SHA-256 content identity, Post revision where applicable, and the original checking actor ID; a delayed job is discarded when the content has changed. If that actor no longer exists, attribution remains empty rather than falling back to the content owner.
- The Health page exposes privacy-safe internal security-control failure counters that expire after one hour without another failure; no URLs, message content, API keys, or provider response bodies are included. Repeated/internal control failures also surface through the Discourse problem-check framework.
- Cached verdicts retain the provider that actually supplied the verdict, including URLhaus supplemental detections. URLhaus has independent typed clean/threat/error semantics, health/circuit state, and threat TTLs so a clean zero-TTL Web Risk response cannot erase URLhaus enforcement.
- Implicit internal-link trust is exact-origin scoped (scheme + normalized hostname + effective port). Safe Browsing keeps its specification-required port-insensitive hash-expression form, while full-URL providers receive the normalized URL with any non-default port preserved. Site-owned FileStore/S3/CDN resources are recognized separately using runtime-derived authority and path-prefix checks; no forum/storage hostname is hardcoded and an asset host is not globally trusted.
- Circuit-breaker, health, lookup-budget, User Note deduplication, final-verification, and revalidation Redis state is namespaced per Discourse site/database for multisite isolation.
- A final cooked-content guard runs after the complete Discourse Post/Chat processing pipeline to catch external links inserted by other plugins after normal validation. Unknown links are temporarily neutralized only when the configured fail-closed policy requires it; background jobs carry target IDs/content identity, never full URLs.
- Periodic revalidation is enabled by default with a conservative bounded target budget (10 targets/hour by default). Existing Post, Chat, profile, topic-featured-link, and group-bio URLs can therefore pick up later threat listings. Metadata is never destructively edited: current cached threats are suppressed/neutralized at presentation time, threat verdicts receive a target-only refresh before expiry, expired confirmed-threat fingerprints remain only as fail-closed historical state during provider outages, and content automatically returns after an explicit clean revalidation.
- Web Risk zero-TTL clean responses are not turned into reusable negative cache entries. A short-lived content-bound one-shot allowance only bridges the exact immediate cook/onebox/final-DOM cycle that follows a fresh clean check.

## User Notes

If the bundled Discourse User Notes plugin is enabled, Link Safety can add a staff note after repeated confirmed threat events. Default mode is `threshold_only`. Monitor-only detections do not create notes. For post and Chat edits, lookup budgets, detections, and optional User Notes are attributed to the last editor rather than automatically to the original author. Group biographies deliberately use no user attribution because the Group model does not expose a reliable editing user during validation.

## Automated tests

The plugin includes specs for Safe Browsing canonicalization/expression generation, monitor/enforce behavior, fail-open/fail-closed behavior, threat rendering, onebox gating, privacy-context classification, exact-origin/FileStore trust, URLhaus failover/TTL behavior, multisite Redis namespacing, security lookup-budget reserve, retry actor/content binding, final cooked-content guarding, metadata presentation, and revalidation target handling. External providers must be stubbed in automated test suites; live API calls belong only in explicit staging/Health tests.

## Recommended rollout

1. Rebuild with plugin disabled.
2. Configure provider and key.
3. Run Health provider test.
4. Enable plugin in Monitor mode.
5. Test public topic, PM, Chat, Chat DM, profile link, topic featured link, group biography, ordinary link, bare link, and onebox cases.
6. Review Detections/Statistics/Health.
7. Switch to Enforce only after staging behavior is verified.

## Post-rebuild staging smoke test

Run the first rebuild with `link_safety_enabled = false`, then use this sequence on staging:

1. Open **Admin > Plugins > Link Safety** and verify that **Settings**, **Health**, **Detections**, and **Statistics** all open without console errors. The Installed Plugins **Settings** control should open the filtered `link_safety` settings page.
2. Configure the primary provider and API key, keep `link_safety_mode = monitor`, enable `link_safety_enabled`, then run **Health > Run provider test**.
3. Post a normal external link in a public topic, a private message, a public Chat channel, and a Chat direct message. Repeat with a bare URL and a URL that normally renders as a onebox. All should continue to work in monitor mode.
4. Enable `link_safety_scan_topic_featured_links` and `link_safety_scan_group_bio_links` on staging, then change a profile website/bio, a topic featured link (where enabled by Discourse), and a non-automatic group biography to contain a normal external link and confirm that each saves.
5. On staging only, use Google's documented malware test URL `http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/`. In monitor mode the content should remain publishable while a detection is recorded.
6. Change to `link_safety_mode = enforce` and repeat the malware test URL in a public post, PM, Chat, Chat DM, profile field, topic featured link, and group biography. The create/edit should be rejected; existing content must remain unchanged when an edit is rejected.
7. Add `example.com` to `link_safety_trusted_domains` and verify that a link to that exact host bypasses provider lookup. Keep `link_safety_trusted_domains_include_subdomains = false` unless subdomain trust is intentionally required.
8. Temporarily simulate a transient provider timeout on staging if you need to verify `fail_open`; authentication/configuration errors such as an invalid API key are intentionally treated as hard verification failures in Enforce mode. Profile link changes remain fail-closed by default, as do topic featured-link and group-bio changes unless their explicit metadata fail-open setting is enabled. Restore normal provider operation immediately after the test.
9. Verify that existing oneboxes, relative and absolute internal Discourse links, uploads/attachments, user and group mentions, category/tag hashtags, quotes, Chat transcript links, code blocks containing URL text, and ordinary posting/chat behavior are unchanged. Also verify that a same-host URL on a different scheme or non-default port is treated as external unless explicitly trusted.
10. With a test-only post-processing plugin/filter, inject an external anchor after normal cooking and verify that the final cooked-content guard schedules verification and follows the configured fail-open/fail-closed presentation policy.
11. Confirm `link_safety_revalidation_enabled` and its hourly target limit are appropriate for provider quota. On staging, shorten the interval temporarily and verify that a cached threat on existing Post/Chat/profile/featured-link/group-bio content is suppressed and that an explicit later clean verdict restores presentation without deleting the stored source content.
12. Review **Detections**, **Statistics**, and **Health**, then switch from monitor to enforce only after the staging results are correct.

The malware URL above is a provider-owned test fixture; do not replace it with a live malicious site.

## Provider selection and required credentials

- **Google Safe Browsing v5**: intended only for eligible non-commercial use. Enable the Safe Browsing API in a Google Cloud project, create a server-side API key, configure `link_safety_google_api_key`, and enable `link_safety_safe_browsing_noncommercial_acknowledged` only when the deployment qualifies. Safe Browsing itself is free; Google assigns a project-specific quota visible in the Developer Console.
- **Google Web Risk Lookup**: use this for commercial or revenue-generating deployments. Enable Web Risk in Google Cloud and configure the same Google API key setting. The first 100,000 Lookup calls per month are free; subsequent calls are billed by Google.
- **URLhaus**: optional supplemental malware-distribution source. It requires an abuse.ch Auth-Key. It is disabled by default, privacy-sensitive full URLs are not sent unless explicitly enabled, and operators should verify their current URLhaus API/fair-use/commercial-use eligibility before production use.

The plugin defaults to **disabled** and **monitor** mode. Configure and test the provider first, enable the plugin in monitor mode, then switch to enforce mode after verifying normal traffic.

## Google provider user protection and attribution

Before using either Google provider, the site operator must make a user-protection notice visible to users before they use Link Safety. The notice must explain that Google-based protection can produce both false positives and false negatives. This documentation/Terms obligation is deliberately not implemented as a runtime Site Setting gate: provider operation depends on the actual provider credentials and, for Safe Browsing v5, the separate non-commercial eligibility acknowledgement. Google suggests language equivalent to: Google works to provide accurate and up-to-date information about unsafe web resources, but cannot guarantee that its information is comprehensive and error-free; some risky sites may not be identified and some safe sites may be identified in error.

When a warning is based on a Google verdict, Link Safety includes Google attribution and an advisory reference. URLhaus-only warnings deliberately do not include Google attribution. Safe Browsing threat verdicts are never enforced beyond 30 minutes without fresh Google data. Web Risk threat verdicts require and respect the provider's valid `expireTime`; missing, malformed, or expired positive-cache timestamps are treated as provider errors. Empty Web Risk Lookup responses are not negatively cached because Lookup does not define a negative-cache lifetime.

## Settings navigation

The plugin is available under **Admin > Plugins > Link Safety**. The Settings button opens the filtered Discourse Site Settings view for `link_safety`, matching the normal Installed Plugins workflow.
