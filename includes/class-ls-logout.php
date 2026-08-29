<?php
/**
 * Global single logout.
 *
 * ---------------------------------------------------------------------------
 * WHY NOT JUST "LET THE IdP DO IT"
 * ---------------------------------------------------------------------------
 * The tidy answer is OIDC Back-Channel Logout: Auth0 POSTs a signed logout
 * token to each site server-to-server, no browser involved, immune to cookie
 * policy. We implement a receiver for it below and it is the right destination.
 *
 * The catch, from Auth0's own documentation: back-channel logout is available
 * on Enterprise plan tenants. On any lower plan the receiver will simply never
 * be called, and a design that relies on it looks fine in testing (because you
 * tested the local logout) and quietly leaves users signed in on the other two
 * sites in production.
 *
 * Front-channel logout — the IdP loading hidden iframes at each site to clear
 * cookies — is not a substitute. Those iframes are third-party contexts:
 * Safari has blocked third-party cookies outright since 2020 and Firefox
 * partitions them. The iframes load and appear to succeed while clearing
 * nothing.
 *
 * So the default path is a signed top-level redirect chain: log out here, then
 * bounce the browser through each peer's logout endpoint, then finish at
 * Auth0's /v2/logout. Every hop is a real first-party navigation, so every hop
 * can actually clear its own cookies. It costs two extra redirects, once, at
 * logout.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Logout propagation.
 */
class LS_SSO_Logout {

	/**
	 * Query var carrying a logout ticket.
	 */
	const TICKET_VAR = 'ls_sso_logout';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		// Cross-domain redirects are rewritten to the home page by
		// wp_safe_redirect() unless the host is allowlisted. Without this the
		// entire chain silently collapses on the first hop.
		add_filter( 'allowed_redirect_hosts', array( __CLASS__, 'allow_peer_hosts' ) );

		// Priority 200 puts us after OpenID Connect Generic's own
		// logout_redirect filter (registered at 99), so $redirect_url is
		// already the Auth0 end_session URL and becomes our chain's terminus.
		add_filter( 'logout_redirect', array( __CLASS__, 'build_logout_chain' ), 200, 3 );

		// Satellite endpoint: clear this site, continue the chain.
		add_action( 'init', array( __CLASS__, 'maybe_handle_ticket' ), 1 );

		// Back-channel receiver, for when/if the tenant supports it.
		add_action( 'rest_api_init', array( __CLASS__, 'register_backchannel_route' ) );
	}

	/**
	 * Allow redirects to our own sites and to the Auth0 tenant.
	 *
	 * An explicit allowlist, never $_SERVER['HTTP_HOST'] — with a signed ticket
	 * travelling in the URL, a permissive rule here is an open redirect that
	 * also leaks the ticket to wherever it points.
	 *
	 * @param array $hosts Allowed hosts.
	 * @return array
	 */
	public static function allow_peer_hosts( $hosts ) {
		foreach ( LS_SSO_Config::all_origins() as $origin ) {
			$host = wp_parse_url( $origin, PHP_URL_HOST );
			if ( $host ) {
				$hosts[] = $host;
			}
		}

		$end_session = self::end_session_endpoint();
		if ( $end_session ) {
			$host = wp_parse_url( $end_session, PHP_URL_HOST );
			if ( $host ) {
				$hosts[] = $host;
			}
		}

		return array_values( array_unique( array_filter( $hosts ) ) );
	}

	/**
	 * The IdP end-session endpoint configured in OpenID Connect Generic.
	 *
	 * @return string
	 */
	protected static function end_session_endpoint() {
		if ( ! class_exists( 'OpenID_Connect_Generic' ) ) {
			return '';
		}
		$plugin = OpenID_Connect_Generic::instance();
		if ( ! $plugin || empty( $plugin->settings ) ) {
			return '';
		}
		return (string) $plugin->settings->endpoint_end_session;
	}

	/**
	 * Turn a plain logout redirect into a chain through every peer.
	 *
	 * Chain shape, built inside out:
	 *   peer1/?ls_sso_logout=<ticket for peer1, next = peer2 hop>
	 *     -> peer2/?ls_sso_logout=<ticket for peer2, next = final>
	 *       -> final (Auth0 /v2/logout, or wherever we were headed)
	 *
	 * @param string  $redirect_url Where logout would have gone.
	 * @param string  $requested    Originally requested destination.
	 * @param WP_User $user         The user logging out.
	 * @return string
	 */
	public static function build_logout_chain( $redirect_url, $requested, $user ) {
		unset( $requested, $user );

		$peers = LS_SSO_Config::peers();
		if ( empty( $peers ) ) {
			return $redirect_url;
		}

		$next = $redirect_url;

		// Reverse order so the first peer visited is the first in the list.
		foreach ( array_reverse( $peers ) as $origin ) {
			$next = self::hop_url( $origin, $next );
		}

		ls_sso_log( 'logout chain built', array( 'hops' => count( $peers ) ) );

		return $next;
	}

	/**
	 * Build one signed hop URL.
	 *
	 * @param string $origin Peer origin to visit.
	 * @param string $next   Where that peer should send the browser afterwards.
	 * @return string
	 */
	protected static function hop_url( $origin, $next ) {
		$ticket = LS_SSO_Signer::sign_ticket(
			array(
				'aud'  => $origin,
				'next' => $next,
				'act'  => 'logout',
			)
		);

		return add_query_arg(
			array( self::TICKET_VAR => rawurlencode( self::pack( $ticket ) ) ),
			trailingslashit( $origin )
		);
	}

	/**
	 * Handle an inbound logout ticket on this site.
	 *
	 * @return void
	 */
	public static function maybe_handle_ticket() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET[ self::TICKET_VAR ] ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw    = sanitize_text_field( wp_unslash( $_GET[ self::TICKET_VAR ] ) );
		$ticket = self::unpack( $raw );

		if ( ! is_array( $ticket ) || ! LS_SSO_Signer::verify_ticket( $ticket, 120 ) ) {
			ls_sso_log( 'logout ticket rejected' );
			wp_safe_redirect( home_url( '/' ) );
			exit;
		}

		// Audience binding: a ticket minted for leadstart.media must not be
		// replayable at leadstart.studio.
		if ( empty( $ticket['aud'] ) || LS_SSO_Config::normalise_origin( $ticket['aud'] ) !== LS_SSO_Config::self_origin() ) {
			ls_sso_log( 'logout ticket audience mismatch' );
			wp_safe_redirect( home_url( '/' ) );
			exit;
		}

		if ( 'logout' !== ( $ticket['act'] ?? '' ) ) {
			wp_safe_redirect( home_url( '/' ) );
			exit;
		}

		// Destroy the local session. wp_logout() revokes the session token as
		// well as clearing cookies, so a cookie copy that survives in some
		// cache is still worthless.
		$logged_out_user = get_current_user_id();
		if ( is_user_logged_in() ) {
			wp_logout();
		}

		LS_SSO_Logger::log(
			'logout_hop',
			array(
				'direction' => 'inbound',
				'user_id'   => $logged_out_user,
				'status'    => 'success',
			)
		);

		// Clear our own silent-SSO probe cookies too, or the next page view
		// immediately re-probes and, if Auth0's session is not yet gone,
		// signs the user straight back in.
		self::clear_probe_cookies();

		$next = isset( $ticket['next'] ) ? (string) $ticket['next'] : home_url( '/' );

		// The next hop is signed, but validate its destination anyway: signed
		// data is authentic, not necessarily safe.
		$end_session_host = wp_parse_url( self::end_session_endpoint(), PHP_URL_HOST );
		$next_host        = wp_parse_url( $next, PHP_URL_HOST );

		if ( ! LS_SSO_Config::is_known_origin( $next ) && $next_host !== $end_session_host ) {
			$next = home_url( '/' );
		}

		nocache_headers();
		wp_redirect( $next );
		exit;
	}

	/**
	 * Expire the silent-login cookies.
	 *
	 * @return void
	 */
	protected static function clear_probe_cookies() {
		if ( headers_sent() ) {
			return;
		}
		foreach ( array( LS_SSO_Silent_Login::COOKIE_PROBED, LS_SSO_Silent_Login::COOKIE_RETURN, LS_SSO_Silent_Login::COOKIE_SILENT ) as $name ) {
			setcookie( $name, '', time() - 3600, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, is_ssl(), false );
		}
	}

	/**
	 * Register the OIDC back-channel logout receiver.
	 *
	 * @return void
	 */
	public static function register_backchannel_route() {
		register_rest_route(
			'leadstart-sso/v1',
			'/backchannel-logout',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'handle_backchannel' ),
				'permission_callback' => '__return_true', // Authenticity comes from the signed logout_token.
				'args'                => array(
					'logout_token' => array(
						'required' => true,
						'type'     => 'string',
					),
				),
			)
		);
	}

	/**
	 * Handle an OIDC logout token from the IdP.
	 *
	 * Validation follows the Back-Channel Logout spec: verify the signature
	 * against the IdP's JWKS, check iss/aud/iat, require the backchannel-logout
	 * event, and reject any token carrying a `nonce` claim — that claim is
	 * forbidden here precisely so an ID token cannot be replayed as a logout
	 * token.
	 *
	 * @param WP_REST_Request $request Inbound request.
	 * @return WP_REST_Response
	 */
	public static function handle_backchannel( WP_REST_Request $request ) {
		$token = (string) $request->get_param( 'logout_token' );

		if ( ! class_exists( 'OpenID_Connect_Generic' ) ) {
			return new WP_REST_Response( array( 'error' => 'unsupported' ), 501 );
		}

		$claims = self::validate_logout_token( $token );
		if ( is_wp_error( $claims ) ) {
			ls_sso_log( 'backchannel logout rejected', array( 'reason' => $claims->get_error_code() ) );
			return new WP_REST_Response( array( 'error' => 'invalid_request' ), 400 );
		}

		$subject = isset( $claims['sub'] ) ? (string) $claims['sub'] : '';
		if ( '' === $subject ) {
			return new WP_REST_Response( array( 'error' => 'invalid_request' ), 400 );
		}

		$user = LS_SSO_Claims::user_by_subject( $subject );
		if ( ! $user ) {
			// Nothing to do here is a success, not a failure.
			return new WP_REST_Response( array( 'ok' => true ), 200 );
		}

		// Destroying every session token for the user invalidates their cookies
		// on this site immediately, without touching the browser.
		$manager = WP_Session_Tokens::get_instance( $user->ID );
		$manager->destroy_all();

		ls_sso_log( 'backchannel logout applied', array( 'user' => $user->ID ) );

		return new WP_REST_Response( array( 'ok' => true ), 200 );
	}

	/**
	 * Validate a logout token against the IdP JWKS.
	 *
	 * Reuses the firebase/php-jwt copy that ships inside OpenID Connect
	 * Generic rather than bundling a second one.
	 *
	 * @param string $token Raw JWT.
	 * @return array|WP_Error Claims on success.
	 */
	protected static function validate_logout_token( $token ) {
		if ( ! class_exists( '\Firebase\JWT\JWT' ) || ! class_exists( '\Firebase\JWT\JWK' ) ) {
			return new WP_Error( 'no_jwt_library', 'JWT library unavailable.' );
		}

		$plugin = OpenID_Connect_Generic::instance();
		if ( ! $plugin || empty( $plugin->settings ) ) {
			return new WP_Error( 'no_settings', 'OIDC settings unavailable.' );
		}

		$jwks_uri = (string) $plugin->settings->endpoint_jwks;
		$issuer   = (string) $plugin->settings->issuer;
		$client_id = (string) $plugin->settings->client_id;

		if ( '' === $jwks_uri || '' === $issuer ) {
			return new WP_Error( 'no_jwks', 'JWKS or issuer not configured.' );
		}

		$jwks = get_transient( 'ls_sso_jwks' );
		if ( false === $jwks ) {
			$response = wp_remote_get( $jwks_uri, array( 'timeout' => 10 ) );
			if ( is_wp_error( $response ) ) {
				return new WP_Error( 'jwks_fetch_failed', 'Could not fetch JWKS.' );
			}
			$jwks = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! is_array( $jwks ) || empty( $jwks['keys'] ) ) {
				return new WP_Error( 'jwks_malformed', 'JWKS malformed.' );
			}
			set_transient( 'ls_sso_jwks', $jwks, HOUR_IN_SECONDS );
		}

		try {
			$decoded = \Firebase\JWT\JWT::decode( $token, \Firebase\JWT\JWK::parseKeySet( $jwks ) );
		} catch ( \Exception $e ) {
			return new WP_Error( 'bad_signature', $e->getMessage() );
		}

		$claims = json_decode( wp_json_encode( $decoded ), true );
		if ( ! is_array( $claims ) ) {
			return new WP_Error( 'bad_claims', 'Unreadable claims.' );
		}

		if ( ( $claims['iss'] ?? '' ) !== $issuer ) {
			return new WP_Error( 'bad_issuer', 'Issuer mismatch.' );
		}

		$audience = (array) ( $claims['aud'] ?? array() );
		if ( '' !== $client_id && ! in_array( $client_id, $audience, true ) ) {
			return new WP_Error( 'bad_audience', 'Audience mismatch.' );
		}

		if ( abs( time() - (int) ( $claims['iat'] ?? 0 ) ) > 300 ) {
			return new WP_Error( 'stale_token', 'Token too old.' );
		}

		// A logout token MUST NOT contain a nonce.
		if ( isset( $claims['nonce'] ) ) {
			return new WP_Error( 'nonce_present', 'Not a logout token.' );
		}

		$events = $claims['events'] ?? array();
		if ( ! is_array( $events ) || ! array_key_exists( 'http://schemas.openid.net/event/backchannel-logout', $events ) ) {
			return new WP_Error( 'missing_event', 'Missing backchannel-logout event.' );
		}

		// Replay protection on jti.
		$jti = (string) ( $claims['jti'] ?? '' );
		if ( '' !== $jti && ! add_option( 'ls_sso_jti_' . md5( $jti ), time() + 900, '', 'no' ) ) {
			return new WP_Error( 'replayed_jti', 'Token replayed.' );
		}

		return $claims;
	}

	/**
	 * Encode a ticket array for a URL.
	 *
	 * @param array $ticket Ticket claims.
	 * @return string
	 */
	protected static function pack( array $ticket ) {
		return rtrim( strtr( base64_encode( wp_json_encode( $ticket ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Decode a packed ticket.
	 *
	 * @param string $raw Packed value.
	 * @return array|null
	 */
	protected static function unpack( $raw ) {
		$json = base64_decode( strtr( $raw, '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $json ) {
			return null;
		}
		$data = json_decode( $json, true );
		return is_array( $data ) ? $data : null;
	}
}
