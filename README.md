# Leadstart SSO

Companion plugin to **OpenID Connect Generic** for `leadstart.org`, `leadstart.media`
and `leadstart.studio`. Auth0 is the identity provider; these are three separate
WordPress installs with three separate databases and no multisite network.

This plugin adds only the four things OpenID Connect Generic does not do.

| | Handled by | Notes |
|---|---|---|
| Authentication | OpenID Connect Generic | Unchanged. Do not replace it. |
| Passwords, MFA, password reset | Auth0 | WordPress never sees a password. |
| **Silent SSO** | **this plugin** | `prompt=none` on first page view. |
| **Global logout** | **this plugin** | Signed redirect chain + back-channel receiver. |
| **Claims → roles / Woo profile** | **this plugin** | Runs on the real Daggerhart hooks. |
| **Order history on satellites** | **this plugin** | Read-only pull from the store site. |

---

## Install

1. Copy the `leadstart-sso` folder to `wp-content/mu-plugins/` on **all three sites**.
2. Because WordPress does not recurse into subdirectories of `mu-plugins`, add a
   one-line loader at `wp-content/mu-plugins/leadstart-sso-loader.php`:

   ```php
   <?php
   require_once __DIR__ . '/leadstart-sso/leadstart-sso.php';
   ```

   If your host does not allow writing to `mu-plugins`, drop the folder in
   `wp-content/plugins/` and activate it normally. Everything works either way;
   must-use simply means nobody can deactivate it by accident.

3. Generate one secret, used on all three sites:

   ```bash
   php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"
   ```

4. Add to `wp-config.php` on each site, above the `/* That's all */` line.
   Note that `LS_SSO_PEERS` lists **the other two** sites, so it differs per site,
   while `LS_SSO_SECRET` and `LS_SSO_STORE` are identical everywhere.

   ```php
   define( 'LS_SSO_SECRET', 'the-64-hex-chars-from-step-3' );
   define( 'LS_SSO_PEERS',  'https://leadstart.media,https://leadstart.studio' );
   define( 'LS_SSO_STORE',  'https://leadstart.org' );

   // Optional
   define( 'LS_SSO_ROLE_CLAIM', 'https://leadstart.org/roles' );
   define( 'LS_SSO_META_KEYS',  'ls_cohort,ls_program_track' );
   define( 'LS_SSO_SILENT_MODE','js' );
   ```

5. Visit **Tools → Leadstart SSO** on each site and run **Test peers**.
   A 403 there means the secret does not match between two sites.

---

## Auth0 configuration

One Auth0 application, three domains listed in each field.

**Allowed Callback URLs** — tick **Alternate Redirect URI** in OpenID Connect
Generic's settings first. That switches the redirect URI from
`…/wp-admin/admin-ajax.php?action=openid-connect-authorize` to a clean path with
no query string, which avoids the whole question of how a given IdP treats query
strings during exact-match validation:

```
https://leadstart.org/openid-connect-authorize,
https://leadstart.media/openid-connect-authorize,
https://leadstart.studio/openid-connect-authorize
```

After ticking that box, re-save **Settings → Permalinks** on each site to flush
rewrite rules, or the new route 404s.

**Allowed Logout URLs**

```
https://leadstart.org, https://leadstart.media, https://leadstart.studio
```

**Allowed Web Origins** — only needed for browser-side calls. This plugin makes
none, so it can stay empty.

In OpenID Connect Generic on each site, set **End Session Endpoint** to
`https://YOUR_TENANT.auth0.com/v2/logout?client_id=YOUR_CLIENT_ID`. Without it,
logout clears WordPress but leaves the Auth0 session alive — and silent SSO then
signs the user straight back in, which reads as "logout is broken".

### Back-channel logout

Auth0 offers OIDC back-channel logout on **Enterprise plan tenants**. If you are
on one, point `backchannel_logout_uri` at:

```
https://leadstart.org/wp-json/leadstart-sso/v1/backchannel-logout
```

(and the equivalent on the other two). The receiver is already implemented and
validates the token against your JWKS.

If you are not on Enterprise, change nothing — the redirect chain is the default
and does not depend on it.

---

## What travels between sites, and what does not

| Data | Crosses sites? | Why |
|---|---|---|
| Password | Never | Auth0 holds it. |
| User record, email, name | No | Each site builds its own from Auth0 claims on login. |
| Roles | No | Derived from an Auth0 claim on every login, everywhere. |
| Billing / shipping address | **No** | WooCommerce runs on one site. The other two have no checkout and no reason to hold a customer's home address. |
| Allowlisted meta (`LS_SSO_META_KEYS`) | Yes, signed | Only keys you name explicitly. |
| Orders | **Read-only, never copied** | One store, one order table. Satellites display, never store. |

Put `[leadstart_orders]` on a page on the two non-store sites to show a signed-in
customer their history.

---

## Corrections to the widely circulated version of this plugin

These are not style preferences. Each one is a defect that fails silently.

**1. `openid-connect-generic-user-login-import` does not exist.**
Not in 3.11.3, not in any version. Code attached to it never runs and never
errors. The real hooks are `openid-connect-generic-user-create` and
`openid-connect-generic-update-user-using-current-claim`. Using only the first
means a user whose Auth0 profile changes keeps the stale copy forever.

**2. `hash( 'sha256', $secret )` in a header is not a signature.**
It is a constant. Same value on every request, forever, proving nothing about the
request it accompanies. Anyone who sees it once — a proxy log, an error report, a
compromised satellite — can replay it against any endpoint with any body. Adding
`hash_equals()` fixes the timing leak and leaves the replay wide open. This
plugin signs an HMAC over timestamp + single-use nonce + route + body digest.

**3. `wp_remote_post( 'https://site-b.com', … )` posts to the home page.**
Not to `/wp-json/shared-sync/v1/update-customer`. WordPress returns 200 and an
HTML document, so the call looks successful in every log while doing nothing.

**4. `$response instanceof Requests_Response` fails intermittently on WordPress
6.2+.** Correcting my own earlier wording: the PSR-0 names were *deprecated*, not
removed. `class-requests.php` still exists and carries `@deprecated 6.2.0`, and
core maps the old names to `WpOrg\Requests\...` with `class_alias()`.

The trap is *when* that alias is created. Core builds it lazily, inside the
Requests autoloader — and `instanceof` does not trigger autoloading. Verified on
PHP 8.4:

```
autoloader fired : NO
instanceof result: false          # alias not yet loaded
instanceof result: true           # after class_exists() forces the alias
```

So the check returns false unless something *else* in that same request already
caused `Requests_Response` to load. The order table therefore works on a site
where some other plugin happens to touch the old class name, and silently renders
empty on a clean one. Intermittent by environment is harder to diagnose than a
flat failure. Using the old names also emits `E_USER_DEPRECATED`.

We sidestep it entirely: one origin to query means one `wp_remote_get()`, no
parallel-request class at all.

**5. `add_filter( 'woocommerce_my_account_my_orders_query', '__return_empty_array' )`
does not hide orders.** It replaces the query *arguments* with an empty array,
which means `wc_get_orders()` runs with its defaults instead of returning nothing.

**6. Matching users by email is wrong when Auth0 is the IdP.**
Email is mutable there and, on some connections, not unique. A customer who
changes their address becomes a different person to the other two sites. Every
lookup here keys on the OIDC subject.

**7. `if ( function_exists( 'as_enqueue_async_action' ) )` disables the sync
silently on two of your three sites.** Action Scheduler ships with WooCommerce,
and WooCommerce is on one site. This plugin uses Action Scheduler when present
and WP-Cron otherwise.

**8. The password-reset block is a dead end and a lockout risk — but not, as I
first wrote, an infinite loop.** Correcting myself: `wp_login_url()` returns
`wp-login.php` with no `action`, which renders the login form and does *not*
re-fire `login_form_lostpassword`. So it terminates. What it actually does is
make "Lost your password?" silently do nothing, and remove your last route back
in if Auth0 is unreachable.

Separately, **`woocommerce_lost_password` is not a WooCommerce hook.** It does
not appear anywhere in `class-wc-shortcode-my-account.php`; the real ones are
`lostpassword_post`, `retrieve_password`, `woocommerce_reset_password_notification`,
`password_reset` and `after_password_reset`. That second `add_action()` is dead
code.

This plugin does not touch password reset at all. If you want it disabled, do it
in Auth0, and keep a documented break-glass admin account.

**9. Hiding the native orders table with `:has()` and an inline `<style>`**
is fragile and unnecessary here — the satellite sites have no WooCommerce My
Account page to hide.

---

## Do not submit this to WordPress.org

It is not a candidate. It requires a shared secret hand-installed on three
specific cooperating sites, has no meaning for anyone else, and publishing it
means committing to support and a security-disclosure process for a private
internal tool.

The review advice you were given also contains one recommendation to actively
refuse: **moving the shared secret into a settings screen.** A signing key in
`wp_options` is in every database backup, every export handed to a contractor,
and every options-disclosure vulnerability — and it becomes three copies that can
silently diverge. Keys belong in `wp-config.php`. The admin screen here reports
configuration; it does not accept it.

---

## Testing

On each site, in a fresh browser profile, in Safari, Firefox and Chrome:

1. Sign in at `leadstart.org`.
2. Open `leadstart.media` in the same browser. You should land signed in with no
   click — one brief redirect through Auth0 and back.
3. Open `leadstart.studio`. Same.
4. Sign out anywhere. All three should be signed out; confirm by loading each.
5. In a private window with no Auth0 session, load each site. You should see the
   normal logged-out page, exactly once per 30 minutes — no redirect loop, and no
   OpenID Connect error page.

Step 5 is the one that catches a bad silent-SSO rollout. Do not skip it.

---

## Licence

GPL-2.0-or-later.
