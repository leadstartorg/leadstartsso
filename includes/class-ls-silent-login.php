<?php
/**
 * Silent SSO against the Auth0 session.
 *
 * ---------------------------------------------------------------------------
 * THE PIECE EVERY VERSION OF THIS PLAN LEFT OUT
 * ---------------------------------------------------------------------------
 * "OIDC handles SSO globally" is half true. Auth0 keeps one session per browser
 * across all three sites, so the *second* login costs no password. But nothing
 * happens until the visitor clicks a login button — arriving at leadstart.media
 * already signed in at leadstart.org still shows a logged-out page.
 *
 * `prompt=none` closes that gap. On the first page view we send the browser to
 * Auth0's /authorize with `prompt=none`; Auth0 either returns an authorization
 * code immediately (the session exists) or returns `error=login_required`
 * (it does not). Either way there is no interaction and no password.
 *
 * This is a top-level redirect, not an iframe, so the Auth0 session cookie is
 * read first-party. Safari's third-party cookie blocking and Firefox's Total
 * Cookie Protection are irrelevant to it.
 *
 * ---------------------------------------------------------------------------
 * WHY 'js' IS THE DEFAULT TRANSPORT
 * ---------------------------------------------------------------------------
 * These sites sit behind a managed edge cache. A server-side 302 emitted from a
 * cacheable page can be stored *as the page* and then served to every later
 * visitor. The result is a site that redirects everyone to Auth0 forever, and
 * clearing it means purging a cache you may not fully control.
 *
 * The 'js' transport makes the decision in the browser instead, where a cached
 * HTML body is harmless: the probe script checks its own cookie and navigates
 * only if appropriate. Set LS_SSO_SILENT_MODE to 'redirect' only on a site you
 * know is not edge-cached.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Silent authentication probe.
 */
class LS_SSO_Silent_Login {

	/**
	 * Cookie recording that we have already probed this browser.
	 */
	const COOKIE_PROBED = 'ls_sso_probed';

	/**
	 * Cookie holding where to return after a failed silent probe.
	 */
	const COOKIE_RETURN = 'ls_sso_return';

	/**
	 * Cookie marking the authorization currently in flight as a silent one.
	 *
	 * This is what makes the privileged-role guard possible. The login hook
	 * itself cannot tell a silent probe from a deliberate click — it fires
	 * identically for both — so the probe leaves this marker on its way out and
	 * the guard reads it on the way back.
	 */
	const COOKIE_SILENT = 'ls_sso_silent';

	/**
	 * How long we wait before probing the same browser again.
	 */
	const PROBE_TTL = 1800;

	/**
	 * Query flag marking our own probe round trip.
	 */
	const FLAG = 'ls_sso_probe';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! LS_SSO_Config::silent_enabled() ) {
			return;
		}

		// Intercept Auth0's "no session" answer before OpenID Connect Generic
		// turns it into a user-facing error page. Priority 1 puts us ahead of
		// the plugin's own callback, which is registered at the default 10.
		add_action( 'wp_ajax_nopriv_openid-connect-authorize', array( __CLASS__, 'intercept_silent_failure' ), 1 );
		add_action( 'wp_ajax_openid-connect-authorize', array( __CLASS__, 'intercept_silent_failure' ), 1 );
		add_action( 'parse_request', array( __CLASS__, 'intercept_silent_failure_alt' ), 1 );

		// Add prompt=none to the authorization URL, but only for our probes.
		add_filter( 'openid-connect-generic-auth-url', array( __CLASS__, 'add_prompt_none' ) );

		// Refuse to *silently* establish a session for a privileged role.
		// Priority 5 so we run before anything else attached to this hook.
		add_action( 'openid-connect-generic-user-logged-in', array( __CLASS__, 'guard_privileged_silent_login' ), 5, 1 );

		if ( 'redirect' === LS_SSO_Config::silent_mode() ) {
			add_action( 'template_redirect', array( __CLASS__, 'maybe_redirect_probe' ), 5 );
		} else {
			add_action( 'wp_footer', array( __CLASS__, 'print_probe_script' ), 99 );
		}
	}

	/**
	 * Whether this request is a candidate for probing.
	 *
	 * @return bool
	 */
	public static function should_probe() {
		if ( is_user_logged_in() ) {
			return false;
		}
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return false;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'GET' !== strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) ) {
			return false;
		}
		if ( is_feed() || is_robots() || is_favicon() || is_preview() ) {
			return false;
		}
		// Never probe on the login page itself; the user is already there to
		// authenticate and a probe would fight the form.
		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return false;
		}
		if ( ! empty( $_COOKIE[ self::COOKIE_PROBED ] ) ) {
			return false;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET[ self::FLAG ] ) ) {
			return false;
		}
		if ( self::looks_like_a_bot() ) {
			return false;
		}

		/**
		 * Final say on whether to run a silent probe for this request.
		 *
		 * @param bool $should Whether to probe.
		 */
		return (bool) apply_filters( 'ls_sso_should_probe', true );
	}

	/**
	 * Crude bot filter.
	 *
	 * Crawlers have no Auth0 session and never will, so probing them wastes a
	 * round trip on every crawled URL and pollutes Auth0's logs.
	 *
	 * @return bool
	 */
	protected static function looks_like_a_bot() {
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] )
			? strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) )
			: '';

		if ( '' === $agent ) {
			return true;
		}

		foreach ( array( 'bot', 'crawl', 'spider', 'slurp', 'facebookexternalhit', 'preview', 'monitor', 'pingdom', 'curl', 'wget', 'headless' ) as $needle ) {
			if ( false !== strpos( $agent, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The URL that starts a silent authorization.
	 *
	 * @return string
	 */
	public static function probe_url() {
		$plugin = OpenID_Connect_Generic::instance();
		if ( ! $plugin || empty( $plugin->client_wrapper ) ) {
			return '';
		}

		$current = self::current_url();

		// Remember where to come back to if Auth0 says there is no session.
		self::set_cookie( self::COOKIE_RETURN, $current, time() + 300 );

		// Mark the round trip as silent, for the privileged-role guard.
		self::set_cookie( self::COOKIE_SILENT, '1', time() + 300 );

		$GLOBALS['ls_sso_probing'] = true;
		$url = $plugin->client_wrapper->get_authentication_url( array( 'redirect_to' => $current ) );
		unset( $GLOBALS['ls_sso_probing'] );

		return $url;
	}

	/**
	 * Append `prompt=none` to the authorization URL during a probe only.
	 *
	 * A normal "Log in" click must NOT carry prompt=none, or Auth0 will refuse
	 * to show a login form and the button will appear broken.
	 *
	 * @param string $url Authorization URL.
	 * @return string
	 */
	public static function add_prompt_none( $url ) {
		if ( empty( $GLOBALS['ls_sso_probing'] ) ) {
			return $url;
		}
		return add_query_arg( 'prompt', 'none', $url );
	}

	/**
	 * Server-side probe (LS_SSO_SILENT_MODE = 'redirect').
	 *
	 * @return void
	 */
	public static function maybe_redirect_probe() {
		if ( ! self::should_probe() ) {
			return;
		}

		$url = self::probe_url();
		if ( '' === $url ) {
			return;
		}

		self::mark_probed();

		// Belt and braces against an edge cache storing this 302.
		nocache_headers();
		header( 'Cache-Control: no-store, no-cache, must-revalidate, private', true );

		wp_redirect( $url );
		exit;
	}

	/**
	 * Browser-side probe (default).
	 *
	 * Emits a few lines of inline script that navigate once per browser. The
	 * cookie is set by JavaScript rather than by PHP so that a cached copy of
	 * this HTML still behaves correctly for the next visitor.
	 *
	 * @return void
	 */
	public static function print_probe_script() {
		if ( ! self::should_probe() ) {
			return;
		}

		$url = self::probe_url();
		if ( '' === $url ) {
			return;
		}

		$payload = wp_json_encode(
			array(
				'url'    => $url,
				'cookie' => self::COOKIE_PROBED,
				'ttl'    => self::PROBE_TTL,
			)
		);
		?>
		<script id="ls-sso-probe">
		(function () {
			var c = <?php echo $payload; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
			try {
				if (document.cookie.indexOf(c.cookie + '=') !== -1) { return; }
				if (window.self !== window.top) { return; }
				if (navigator.webdriver) { return; }
				document.cookie = c.cookie + '=1; path=/; max-age=' + c.ttl + '; SameSite=Lax' +
					(location.protocol === 'https:' ? '; Secure' : '');
				window.location.replace(c.url);
			} catch (e) { /* A blocked cookie jar just means no silent SSO. */ }
		})();
		</script>
		<?php
	}

	/**
	 * Refuse a silently-established session for a privileged role.
	 *
	 * ------------------------------------------------------------------------
	 * WHAT THIS DELIBERATELY DOES NOT DO
	 * ------------------------------------------------------------------------
	 * The obvious version of this feature hooks the same action, checks the
	 * user's role, and calls wp_logout() + redirect to wp_login_url(). That
	 * produces a genuine lockout: `openid-connect-generic-user-logged-in` fires
	 * for EVERY login, silent or deliberate, so an administrator who clicks
	 * "Log in" is signed out and returned to a login page whose only method is
	 * the one that just rejected them. Round and round.
	 *
	 * The distinction that matters is not "is this user an admin" but "did this
	 * user ask to log in". A silent probe carries COOKIE_SILENT; a click does
	 * not. Only the former is refused, and it returns the visitor to the page
	 * they were reading rather than to a login form.
	 *
	 * Note also what tears the session down. wp_logout() fires the `wp_logout`
	 * action, which this plugin uses to build the cross-site logout chain — so
	 * calling it here would bounce the visitor through every peer site and out
	 * to the IdP, destroying the Auth0 session they legitimately hold. We use
	 * the primitives directly instead: revoke this one session token, clear this
	 * site's cookies, and stop.
	 *
	 * @param WP_User $user The user who has just been logged in.
	 * @return void
	 */
	public static function guard_privileged_silent_login( $user ) {
		if ( ! $user instanceof WP_User ) {
			return;
		}

		// Was this authorization a silent probe? A deliberate login is never
		// blocked, whatever the role.
		if ( empty( $_COOKIE[ self::COOKIE_SILENT ] ) ) {
			return;
		}

		$blocked = LS_SSO_Config::blocked_silent_roles();
		if ( empty( $blocked ) ) {
			return;
		}

		// Roles have already been mapped from claims at this point: the
		// update-user-using-current-claim action runs inside login_user(),
		// before the auth cookie is issued.
		$held = array_map( 'sanitize_key', (array) $user->roles );

		// Capability backstop, in case a custom role grants admin powers under
		// a name that is not on the blocked list.
		$is_privileged = ! empty( array_intersect( $held, $blocked ) )
			|| ( in_array( 'administrator', $blocked, true ) && user_can( $user, 'manage_options' ) );

		if ( ! $is_privileged ) {
			return;
		}

		$return = isset( $_COOKIE[ self::COOKIE_RETURN ] )
			? esc_url_raw( wp_unslash( $_COOKIE[ self::COOKIE_RETURN ] ) )
			: home_url( '/' );

		if ( ! LS_SSO_Config::is_known_origin( $return ) ) {
			$return = home_url( '/' );
		}

		// Tear down only this session. Not wp_logout() — see the note above.
		wp_destroy_current_session();
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );

		self::mark_probed();
		self::set_cookie( self::COOKIE_SILENT, '', time() - 3600 );
		self::set_cookie( self::COOKIE_RETURN, '', time() - 3600 );

		LS_SSO_Logger::log(
			'silent_login_refused',
			array(
				'direction' => 'inbound',
				'user_id'   => $user->ID,
				'status'    => 'success',
				'detail'    => 'privileged role: ' . implode( ',', $held ),
			)
		);

		ls_sso_log( 'silent login refused for privileged user', array( 'user' => $user->ID ) );

		nocache_headers();
		wp_safe_redirect( add_query_arg( self::FLAG, 'privileged', $return ) );
		exit;
	}

	/**
	 * Record that this browser has been probed.
	 *
	 * @return void
	 */
	protected static function mark_probed() {
		self::set_cookie( self::COOKIE_PROBED, '1', time() + self::PROBE_TTL );
	}

	/**
	 * Handle Auth0's `error=login_required` on the default redirect URI.
	 *
	 * Without this the visitor sees OpenID Connect Generic's authentication
	 * error page after simply browsing to the site while logged out — which is
	 * the single most alarming way a silent SSO rollout can fail.
	 *
	 * @return void
	 */
	public static function intercept_silent_failure() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$error = isset( $_GET['error'] ) ? sanitize_text_field( wp_unslash( $_GET['error'] ) ) : '';

		if ( ! self::is_silent_failure( $error ) ) {
			return;
		}

		$return = isset( $_COOKIE[ self::COOKIE_RETURN ] )
			? esc_url_raw( wp_unslash( $_COOKIE[ self::COOKIE_RETURN ] ) )
			: home_url( '/' );

		// The return URL came from a cookie, so it is attacker-influenced.
		if ( ! LS_SSO_Config::is_known_origin( $return ) ) {
			$return = home_url( '/' );
		}

		self::mark_probed();
		self::set_cookie( self::COOKIE_RETURN, '', time() - 3600 );
		self::set_cookie( self::COOKIE_SILENT, '', time() - 3600 );

		ls_sso_log( 'silent probe found no Auth0 session', array( 'error' => $error ) );

		nocache_headers();
		wp_safe_redirect( add_query_arg( self::FLAG, 'none', $return ) );
		exit;
	}

	/**
	 * Same interception for the alternate (query-string-free) redirect URI.
	 *
	 * @param WP $query Current request.
	 * @return void
	 */
	public static function intercept_silent_failure_alt( $query ) {
		if ( isset( $query->query_vars['openid-connect-authorize'] ) ) {
			self::intercept_silent_failure();
		}
	}

	/**
	 * Whether an OAuth error code means "no session", as opposed to a real fault.
	 *
	 * @param string $error Error code from the IdP.
	 * @return bool
	 */
	protected static function is_silent_failure( $error ) {
		return in_array(
			$error,
			array( 'login_required', 'interaction_required', 'consent_required', 'account_selection_required' ),
			true
		);
	}

	/**
	 * Current request URL, absolute.
	 *
	 * @return string
	 */
	protected static function current_url() {
		$path = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		return home_url( $path );
	}

	/**
	 * Set a first-party cookie with sane flags.
	 *
	 * @param string $name    Cookie name.
	 * @param string $value   Value.
	 * @param int    $expires Unix expiry.
	 * @return void
	 */
	protected static function set_cookie( $name, $value, $expires ) {
		if ( headers_sent() ) {
			return;
		}

		setcookie(
			$name,
			$value,
			array(
				'expires'  => $expires,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => false, // The JS transport needs to read it.
				'samesite' => 'Lax',
			)
		);
	}
}
