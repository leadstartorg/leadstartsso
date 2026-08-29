<?php
/**
 * Request signing and verification.
 *
 * ---------------------------------------------------------------------------
 * WHY NOT `hash( 'sha256', $secret )` IN A HEADER
 * ---------------------------------------------------------------------------
 * A digest of a fixed secret is a constant. It is the same on every request
 * forever, which means it is a bearer token, not a signature. It proves nothing
 * about the request it accompanies: anyone who observes it once — a proxy log,
 * an error report, a misconfigured CDN, a compromised satellite — can replay it
 * against any endpoint, with any body, indefinitely. Comparing it with `===`
 * also leaks its value slowly through timing.
 *
 * What we do instead: HMAC-SHA256 over a canonical string that pins the
 * timestamp, a single-use nonce, the route, and a digest of the exact body.
 * Change any byte of the request and the signature no longer verifies.
 *
 * Replay protection is a real single-use check, not a "have I seen this
 * lately" lookup. `add_option()` performs an INSERT against a UNIQUE index on
 * `option_name` and returns false when the row already exists, which makes it
 * atomic under concurrency. A SELECT-then-INSERT is a race: two simultaneous
 * replays both read "unseen" and both proceed.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * HMAC signer/verifier for site-to-site requests.
 */
class LS_SSO_Signer {

	const HDR_TIMESTAMP = 'X-LS-Timestamp';
	const HDR_NONCE     = 'X-LS-Nonce';
	const HDR_SIGNATURE = 'X-LS-Signature';
	const HDR_ORIGIN    = 'X-LS-Origin';

	/**
	 * Maximum accepted clock skew, in seconds.
	 */
	const MAX_SKEW = 300;

	/**
	 * How long a spent nonce is remembered. Must exceed MAX_SKEW * 2, or a
	 * request could be replayed after its nonce record expired but while its
	 * timestamp was still inside the window.
	 */
	const NONCE_TTL = 900;

	/**
	 * Option name prefix for spent nonces.
	 */
	const NONCE_PREFIX = 'ls_sso_nonce_';

	/**
	 * Build the canonical string that gets signed.
	 *
	 * Body is hashed rather than concatenated so that the canonical string
	 * stays a fixed, newline-free-ish shape regardless of payload size, and so
	 * a body containing newlines cannot shift field boundaries.
	 *
	 * @param string $timestamp Unix seconds, as a string.
	 * @param string $nonce     Random single-use value.
	 * @param string $route     REST route, e.g. '/leadstart-sso/v1/orders'.
	 * @param string $body      Raw request body ('' for GET).
	 * @return string
	 */
	protected static function canonical( $timestamp, $nonce, $route, $body ) {
		return implode(
			"\n",
			array(
				'LSSSO1',
				$timestamp,
				$nonce,
				$route,
				hash( 'sha256', (string) $body ),
			)
		);
	}

	/**
	 * Produce the signature headers for an outbound request.
	 *
	 * @param string $route REST route being called.
	 * @param string $body  Raw body that will be sent, byte for byte.
	 * @return array<string,string>
	 */
	public static function headers( $route, $body = '' ) {
		$timestamp = (string) time();
		$nonce     = bin2hex( random_bytes( 16 ) );

		$signature = hash_hmac(
			'sha256',
			self::canonical( $timestamp, $nonce, $route, $body ),
			LS_SSO_Config::secret()
		);

		return array(
			self::HDR_TIMESTAMP => $timestamp,
			self::HDR_NONCE     => $nonce,
			self::HDR_SIGNATURE => $signature,
			self::HDR_ORIGIN    => LS_SSO_Config::self_origin(),
			'Content-Type'      => 'application/json; charset=utf-8',
			'Accept'            => 'application/json',
		);
	}

	/**
	 * Verify an inbound REST request.
	 *
	 * Suitable for use directly as a `permission_callback`.
	 *
	 * @param WP_REST_Request $request Inbound request.
	 * @return true|WP_Error
	 */
	public static function verify( WP_REST_Request $request ) {

		if ( ! LS_SSO_Config::is_configured() ) {
			return new WP_Error( 'ls_sso_unconfigured', 'Federation is not configured.', array( 'status' => 503 ) );
		}

		$timestamp = (string) $request->get_header( self::HDR_TIMESTAMP );
		$nonce     = (string) $request->get_header( self::HDR_NONCE );
		$signature = (string) $request->get_header( self::HDR_SIGNATURE );
		$origin    = (string) $request->get_header( self::HDR_ORIGIN );

		if ( '' === $timestamp || '' === $nonce || '' === $signature ) {
			return self::deny( 'missing_headers' );
		}

		// Nonce shape is checked before it becomes part of an option name.
		if ( ! preg_match( '/\A[a-f0-9]{32}\z/', $nonce ) ) {
			return self::deny( 'bad_nonce_format' );
		}

		// The caller must be one of our own sites.
		if ( ! LS_SSO_Config::is_known_origin( $origin ) ) {
			return self::deny( 'unknown_origin' );
		}

		// Freshness. Rejecting future timestamps too, not just old ones —
		// otherwise a captured request can be given a far-future timestamp and
		// stay valid indefinitely.
		$skew = abs( time() - (int) $timestamp );
		if ( $skew > self::MAX_SKEW ) {
			return self::deny( 'stale_timestamp', array( 'skew' => $skew ) );
		}

		$expected = hash_hmac(
			'sha256',
			self::canonical( $timestamp, $nonce, $request->get_route(), $request->get_body() ),
			LS_SSO_Config::secret()
		);

		// Constant-time comparison: a plain === returns early on the first
		// differing byte, which is measurable over enough requests.
		if ( ! hash_equals( $expected, $signature ) ) {
			return self::deny( 'bad_signature' );
		}

		// Single-use check, last, so we never burn a nonce on a request that
		// was going to fail anyway.
		if ( ! self::consume_nonce( $nonce ) ) {
			return self::deny( 'replayed_nonce' );
		}

		return true;
	}

	/**
	 * Atomically claim a nonce. Returns false if it was already spent.
	 *
	 * @param string $nonce Validated 32-char hex nonce.
	 * @return bool
	 */
	protected static function consume_nonce( $nonce ) {
		$key = self::NONCE_PREFIX . $nonce;

		// add_option() is an INSERT against a UNIQUE index. It returns false if
		// the row exists, which is the atomic test-and-set we need. autoload is
		// 'no' so these never join the bulk option load.
		$claimed = add_option( $key, time() + self::NONCE_TTL, '', 'no' );

		if ( $claimed ) {
			// Opportunistic cleanup so the options table does not grow forever
			// on a site whose cron is unreliable.
			if ( 0 === wp_rand( 0, 50 ) ) {
				self::gc();
			}
		}

		return (bool) $claimed;
	}

	/**
	 * Delete expired nonce rows.
	 *
	 * @return int Rows removed.
	 */
	public static function gc() {
		global $wpdb;

		$now  = time();
		$like = $wpdb->esc_like( self::NONCE_PREFIX ) . '%';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 500",
				$like
			)
		);

		$removed = 0;
		foreach ( (array) $rows as $row ) {
			if ( (int) $row->option_value < $now ) {
				delete_option( $row->option_name );
				++$removed;
			}
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		return $removed;
	}

	/**
	 * Build a uniform denial. The client is told nothing beyond "no".
	 *
	 * @param string $reason  Internal reason code, logged only.
	 * @param array  $context Extra log context.
	 * @return WP_Error
	 */
	protected static function deny( $reason, $context = array() ) {
		ls_sso_log( 'request denied: ' . $reason, $context );
		LS_SSO_Logger::log(
			'request_denied',
			array(
				'direction' => 'inbound',
				'status'    => 'failure',
				'detail'    => $reason,
			)
		);
		return new WP_Error(
			'ls_sso_forbidden',
			'Request rejected.',
			array( 'status' => 403 )
		);
	}

	/**
	 * Sign an arbitrary short payload for a browser round trip.
	 *
	 * Used by the logout chain, where the "request" is a top-level redirect
	 * rather than a REST call and so carries its proof in the query string.
	 *
	 * @param array $claims Small associative array.
	 * @return array The claims plus `ts` and `sig`.
	 */
	public static function sign_ticket( array $claims ) {
		$claims['ts'] = time();
		ksort( $claims );

		$claims['sig'] = hash_hmac(
			'sha256',
			'LSTICKET1|' . wp_json_encode( $claims ),
			LS_SSO_Config::secret()
		);

		return $claims;
	}

	/**
	 * Verify a ticket produced by sign_ticket().
	 *
	 * @param array $claims Claims including `ts` and `sig`.
	 * @param int   $ttl    Maximum age in seconds.
	 * @return bool
	 */
	public static function verify_ticket( array $claims, $ttl = 120 ) {
		if ( empty( $claims['sig'] ) || empty( $claims['ts'] ) ) {
			return false;
		}

		$signature = (string) $claims['sig'];
		unset( $claims['sig'] );

		if ( abs( time() - (int) $claims['ts'] ) > $ttl ) {
			return false;
		}

		ksort( $claims );
		$expected = hash_hmac(
			'sha256',
			'LSTICKET1|' . wp_json_encode( $claims ),
			LS_SSO_Config::secret()
		);

		return hash_equals( $expected, $signature );
	}
}
