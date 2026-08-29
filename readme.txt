=== Leadstart SSO ===
Contributors: leadstartmedia
Tags: sso, openid connect, single sign-on, single logout, woocommerce
Requires at least: 5.9
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.4.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Silent single sign-on, global single logout, and signed cross-site federation for separate WordPress installs sharing one OpenID Connect provider.

== Description ==

A companion to the **OpenID Connect Generic** plugin, for the case it does not
cover: several *separate* WordPress installations, on different domains, sharing
one identity provider.

OpenID Connect Generic authenticates a user on each site. It does not make a
visitor who signed in on one site arrive signed in at the next, and it does not
make signing out of one site sign them out of the others. This plugin adds those
two behaviours, plus two smaller ones.

**Silent single sign-on.** On a visitor's first page view, the plugin performs an
OpenID Connect `prompt=none` authorization against your provider. If the provider
session exists, the visitor is signed in with no click and no password prompt. If
it does not, the visitor sees an ordinary logged-out page. This is a top-level
redirect, not a hidden iframe, so it is unaffected by third-party cookie blocking
in Safari and Firefox.

**Global single logout.** Signing out anywhere signs the user out everywhere, via
a signed top-level redirect chain that visits each configured site in turn and
ends at your provider's end-session endpoint. A standard OIDC Back-Channel Logout
receiver is also included for providers and plans that support it.

**Claims mapping.** Map provider claims onto WordPress roles, and — on the one
site running WooCommerce — onto billing and shipping fields.

**Order history federation.** Sites without WooCommerce can display a signed-in
customer's order history, read *live* from the store site with the
`[leadstart_orders]` shortcode. Nothing is copied or replicated.

= Design notes =

This plugin deliberately does not replicate users, passwords, or orders between
sites. Your identity provider is the source of truth for identity; the store site
is the source of truth for orders. Federation here means asking the authoritative
site a question, not keeping a second copy of its answer.

Site-to-site requests are authenticated with HMAC-SHA256 over the timestamp, a
single-use nonce, the route, and a digest of the request body, with a five-minute
freshness window and atomic replay protection.

= Privileged roles and silent sign-on =

By default, administrators are never signed in *silently*. If a silent probe
would establish an administrator session, the plugin declines it and the visitor
sees an ordinary logged-out page; clicking "Log in" still works normally. This
means a hijacked provider session cannot hand someone an administrator session on
every site with no interaction at all.

Change the list with `LS_SSO_BLOCK_SILENT_ROLES` (comma-separated role slugs, or
empty to allow every role), or with the `ls_sso_block_silent_roles` filter.

= Requirements =

* The [OpenID Connect Generic](https://wordpress.org/plugins/daggerhart-openid-connect-generic/) plugin, active and configured, on every participating site.
* An OpenID Connect provider (Auth0, Keycloak, Okta, Entra ID and others).
* HTTPS on every participating site.
* WooCommerce, on the store site only, if you want order federation.

== Installation ==

1. Install and configure **OpenID Connect Generic** on every site first, and
   confirm that signing in works on each one individually.
2. Install and activate this plugin on every site.
3. Generate one shared secret, to be used by all sites:
   `php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"`
   The plugin's settings screen also has a **Generate** button that produces one
   in your browser without sending it to any server.
4. Configure each site, either in `wp-config.php` (preferred) or under
   **Tools > Leadstart SSO > Settings** if you cannot edit that file.
   `LS_SSO_PEERS` lists the *other* sites, so it differs per site; the secret and
   the store are identical everywhere:

   `define( 'LS_SSO_SECRET', 'your-64-character-hex-secret' );`
   `define( 'LS_SSO_PEERS',  'https://second-site.com,https://third-site.com' );`
   `define( 'LS_SSO_STORE',  'https://store-site.com' );`

   Sites may mix the two methods freely — a constant on one, the settings screen
   on another — as long as the secret matches.

5. Visit **Tools → Leadstart SSO** and run **Test peers** on each site.
6. In OpenID Connect Generic, enable **Alternate Redirect URI**, then re-save
   Settings → Permalinks. Register each site's `/openid-connect-authorize` URL
   with your provider.

== Frequently Asked Questions ==

= Where should the shared secret live? =

In `wp-config.php`, if you can edit it. A signing key in the options table is in
every database backup and every export handed to a contractor, and is reachable
by any vulnerability that discloses options.

If you cannot edit that file — many managed hosts allow plugin installation and
no file access at all — set it under **Tools > Leadstart SSO > Settings**
instead. The option is stored with autoload off and is never displayed again
after saving. A constant, when defined, always wins and the field becomes
read-only.

Either way the screen shows a short fingerprint of the secret, so you can confirm
every site holds the same value without revealing it. Matching fingerprints mean
matching secrets; different ones explain the 403s.

= Test peers says 404. What does that mean? =

The status code is the diagnosis, and the three common ones are unrelated:

* **404** — no REST route on that site, so the plugin is not installed or not
  activated there. Your secret was never checked, so a 404 tells you nothing
  about whether the secrets match.
* **503** — the plugin is installed there but has no secret or peers configured
  yet.
* **403** — the request was signed, received, and refused. This is the mismatched
  secret case, and the only one where comparing fingerprints helps.

Work through the sites in order: install and activate everywhere first, then
configure everywhere, then test.

= Can I mix wp-config.php constants and the Settings tab across sites? =

Yes. Each site resolves each setting independently: the constant if one is
defined, the stored option otherwise. A site with file access can use constants
while another uses the Settings screen, as long as the secret matches — compare
the fingerprints to confirm.

= Do all sites need the same plugin version? =

They interoperate across versions: the signing format, headers, REST routes and
logout tickets have not changed since 1.0.0. Running the same version everywhere
is still recommended, because newer versions add local behaviour (for example,
refusing silent sign-on for administrators) that only applies where installed.

= Can I install it in mu-plugins on some sites and as a normal plugin on others? =

Yes, per site. What you must not do is install it in **both** places on the
**same** site: the classes then load twice from two paths, which is a fatal
error. From version 1.3.2 the second copy detects this, stops loading, and shows
an admin notice naming the file that is actually running.

= Can I run this on a host with no SFTP access? =

Yes. Every setting can be entered on the Settings tab. The plugin only needs to
be installable and able to make outbound HTTPS requests.

= What role do new users get? =

Whatever **Settings > General > New User Default Role** says on that site —
normally `subscriber`. OpenID Connect Generic does not set a role when it creates
the account, so `wp_insert_user()` falls back to that option. Changing the
setting is usually the whole answer; no code is needed.

To decide the role per user instead, use the `ls_sso_map_roles` filter. It runs
on every SSO login, including when no role claim is configured:

`add_filter( 'ls_sso_map_roles', function ( $roles, $incoming, $user ) {`
`    return in_array( 'staff', $incoming, true ) ? array( 'editor' ) : array( 'customer' );`
`}, 10, 3 );`

Returning an empty array leaves the user's roles untouched. Administrators are
never re-roled by this filter, so a misconfigured provider cannot demote the
person who has to log in and fix it.

If you map from a provider claim, note that **Auth0 silently drops custom claims
namespaced under an Auth0 domain** — `auth0.com`, `webtask.io` and `webtask.run`
are all rejected as namespaces. Use a domain you control, such as
`https://example.com/roles`. A claim namespaced to `your-tenant.auth0.com` never
arrives, and role mapping then appears broken with no error anywhere.

= Does this require WooCommerce? =

No. WooCommerce is needed only for the optional order-history feature, and only
on the one site that runs the store.

= Does this work with WordPress Multisite? =

It is built for the opposite case: separate installations with separate
databases. A multisite network already shares users, sessions and logout through
WordPress core, and does not need this plugin.

= What happens when a peer site is offline? =

Outbound updates are queued and retried with backoff, using Action Scheduler when
available and WP-Cron otherwise. Order history requests use a short timeout and a
cached result, so a slow store site never blocks a page for a visitor.

= Does silent SSO redirect every visitor, including search engines? =

No. Crawlers are excluded, the probe runs at most once per browser per 30
minutes, and by default the probe is performed in the browser rather than as a
server-side redirect, so it cannot be captured by a page cache.

= What personal data does this store? =

The plugin stores no personal data of its own. Its activity log records the
event type, the peer site, the route, a WordPress user ID, and success or
failure — never request bodies, meta values, tokens, or signatures. Rows are
deleted automatically after 30 days, filterable via
`ls_sso_log_retention_days`. Uninstalling removes the log table entirely.

== Screenshots ==

1. Status screen, showing configuration and peer connectivity.
2. Activity log.
3. Federated order history on a site without WooCommerce.

== Changelog ==

= 1.4.1 =
* Fixed the activity log never being created. Its migration was registered on a
  hook priority that had already passed, so it never ran, the table never
  existed, and every log entry was silently discarded.

= 1.4.0 =
* REST routes are now registered even before the plugin is configured, so an
  unconfigured peer answers 503 instead of 404. Requests are still refused until
  a secret exists.
* Peer requests fall back to the `?rest_route=` form when a site has plain
  permalinks and no `/wp-json/` prefix.
* Test peers now explains what each status code means instead of printing it.

= 1.3.2 =
* Added a double-load guard. Installing the plugin in both mu-plugins and
  plugins on the same site previously caused a fatal class redeclaration; the
  second copy now stops and reports which file is running.

= 1.3.1 =
* The Settings screen now reports exactly which settings were written, and shows
  whether a shared secret is stored (with its fingerprint) right beside the
  field. The secret field is blank by design on every load; previously there was
  no way to tell a successful save from a no-op.

= 1.3.0 =
* Every setting can now be configured from a Settings tab as well as from a
  wp-config.php constant, so the plugin works on hosts that allow plugin
  installation but no file access. Constants always take precedence.
* The shared secret is write-only in the admin and is identified by a short
  fingerprint, so matching secrets can be confirmed across sites without
  displaying the value.

= 1.2.1 =
* The `ls_sso_map_roles` filter now runs even when no role claim is configured,
  so a site can force a default role without setting up a namespaced claim.

= 1.2.0 =
* Administrators are no longer signed in silently by default. Interactive login
  is unaffected. Configurable via `LS_SSO_BLOCK_SILENT_ROLES`.

= 1.1.0 =
* Added an activity log with a 30-day retention policy and an admin viewer.
* Added a browser-side shared-secret generator to the settings screen.
* Added `uninstall.php` for complete cleanup on deletion.
* Internationalised all user-facing strings.

= 1.0.0 =
* Initial release: silent SSO, global single logout, claims mapping, order
  federation.

== Upgrade Notice ==

= 1.3.0 =
No action needed. Existing wp-config.php constants continue to take precedence
over anything set in the new Settings tab.

= 1.2.0 =
Administrators will no longer be signed in automatically when arriving from
another site; they must click "Log in" once. Set LS_SSO_BLOCK_SILENT_ROLES to an
empty string to restore the previous behaviour.

= 1.1.0 =
Adds an activity log. The table is created automatically on first load; no
configuration change is required.
