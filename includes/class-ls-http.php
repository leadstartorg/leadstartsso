<?php
/**
 * Outbound transport: signed calls to peer sites, plus a background queue.
 *
 * ---------------------------------------------------------------------------
 * ON THE ACTION SCHEDULER ASSUMPTION
 * ---------------------------------------------------------------------------
 * Action Scheduler ships with WooCommerce. WooCommerce runs on one of these
 * three sites. So a queue written as:
 *
 *     if ( function_exists( 'as_enqueue_async_action' ) ) { ... }
 *
 * silently does nothing at all on the two sites that do not have WooCommerce —
 * no error, no log line, no sync. The guard makes the failure invisible, which
 * is worse than a fatal.
 *
 * This class uses Action Scheduler when it is genuinely available and falls
 * back to WP-Cron's single events otherwise, so the same code path works on
 * every site. Both paths carry a retry count, because neither WP-Cron nor a
 * fire-and-forget request retries on its own.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Signed HTTP client and deferred dispatcher.
 */
class LS_SSO_Http {

	const HOOK_WORKER = 'ls_sso_dispatch_worker';
	const MAX_ATTEMPTS = 4;

	/**
	 * Register the background worker.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( self::HOOK_WORKER, array( __CLASS__, 'run_job' ), 10, 4 );
	}

	/**
	 * Queue a signed POST to every peer, to run outside this request.
	 *
	 * Nothing here touches the network. The visitor's save completes at local
	 * database speed whether the peers are up, slow, or on fire.
	 *
	 * @param string $route   REST route on the receiving site.
	 * @param array  $payload JSON-serialisable body.
	 * @param array  $targets Optional explicit origins; defaults to all peers.
	 * @return void
	 */
	public static function queue( $route, array $payload, array $targets = array() ) {
		if ( empty( $targets ) ) {
			$targets = LS_SSO_Config::peers();
		}

		foreach ( $targets as $origin ) {
			self::schedule( $origin, $route, $payload, 1 );
		}
	}

	/**
	 * Schedule one delivery attempt.
	 *
	 * @param string $origin  Target origin.
	 * @param string $route   REST route.
	 * @param array  $payload Body.
	 * @param int    $attempt 1-based attempt number.
	 * @return void
	 */
	protected static function schedule( $origin, $route, array $payload, $attempt ) {
		$args = array( $origin, $route, $payload, $attempt );

		// Exponential-ish backoff: 0s, 60s, 300s, 900s.
		$delays = array( 1 => 0, 2 => 60, 3 => 300, 4 => 900 );
		$delay  = isset( $delays[ $attempt ] ) ? $delays[ $attempt ] : 900;

		if ( function_exists( 'as_schedule_single_action' ) ) {
			as_schedule_single_action( time() + $delay, self::HOOK_WORKER, $args, 'leadstart-sso' );
			return;
		}

		// WP-Cron fallback. Deduplicated by WordPress on identical args, so a
		// double save does not double-post.
		wp_schedule_single_event( time() + $delay, self::HOOK_WORKER, $args );

		// WP-Cron only fires on a page view. On a quiet site that can be a long
		// wait, so nudge the loopback without blocking on it.
		if ( 1 === $attempt ) {
			spawn_cron();
		}
	}

	/**
	 * Background worker: deliver one payload to one peer.
	 *
	 * @param string $origin  Target origin.
	 * @param string $route   REST route.
	 * @param array  $payload Body.
	 * @param int    $attempt Attempt number.
	 * @return void
	 */
	public static function run_job( $origin, $route, $payload, $attempt = 1 ) {
		$result = self::post( $origin, $route, $payload, 15 );

		if ( ! is_wp_error( $result ) ) {
			return;
		}

		$attempt = (int) $attempt;
		if ( $attempt >= self::MAX_ATTEMPTS ) {
			ls_sso_log(
				'delivery abandoned',
				array(
					'origin'  => $origin,
					'route'   => $route,
					'error'   => $result->get_error_message(),
					'attempts' => $attempt,
				)
			);
			return;
		}

		self::schedule( $origin, $route, $payload, $attempt + 1 );
	}

	/**
	 * Perform a signed POST immediately.
	 *
	 * Note the full URL construction. Posting to a bare origin sends the
	 * payload to the site's home page, which returns 200 and an HTML document —
	 * so the call looks successful in every log while doing nothing whatsoever.
	 *
	 * @param string $origin  Target origin.
	 * @param string $route   REST route, e.g. '/leadstart-sso/v1/usermeta'.
	 * @param array  $payload Body.
	 * @param int    $timeout Seconds.
	 * @return array|WP_Error Decoded response body, or error.
	 */
	public static function post( $origin, $route, array $payload, $timeout = 10 ) {
		$origin = LS_SSO_Config::normalise_origin( $origin );
		if ( '' === $origin ) {
			return new WP_Error( 'ls_sso_bad_origin', 'Unusable target origin.' );
		}

		$body = wp_json_encode( $payload );
		$args = array(
			'timeout'     => $timeout,
			'redirection' => 0,
			'headers'     => LS_SSO_Signer::headers( $route, $body ),
			'body'        => $body,
		);

		$url      = $origin . '/wp-json' . $route;
		$response = wp_remote_post( $url, $args );

		// A peer with plain permalinks has no /wp-json/ prefix at all. Retry on
		// the query-string form before concluding the route does not exist.
		if ( self::is_404( $response ) ) {
			$url      = add_query_arg( 'rest_route', $route, $origin . '/' );
			$response = wp_remote_post( $url, $args );
		}

		return self::interpret( $response, $url );
	}

	/**
	 * Perform a signed GET immediately.
	 *
	 * @param string $origin  Target origin.
	 * @param string $route   REST route.
	 * @param array  $query   Query arguments.
	 * @param int    $timeout Seconds.
	 * @return array|WP_Error
	 */
	public static function get( $origin, $route, array $query = array(), $timeout = 5 ) {
		$origin = LS_SSO_Config::normalise_origin( $origin );
		if ( '' === $origin ) {
			return new WP_Error( 'ls_sso_bad_origin', 'Unusable target origin.' );
		}

		$args = array(
			'timeout'     => $timeout,
			'redirection' => 0,
			'headers'     => LS_SSO_Signer::headers( $route, '' ),
		);

		$url      = add_query_arg( $query, $origin . '/wp-json' . $route );
		$response = wp_remote_get( $url, $args );

		if ( self::is_404( $response ) ) {
			$url      = add_query_arg( array_merge( array( 'rest_route' => $route ), $query ), $origin . '/' );
			$response = wp_remote_get( $url, $args );
		}

		return self::interpret( $response, $url );
	}

	/**
	 * Whether a response is a plain 404.
	 *
	 * @param array|WP_Error $response Raw result.
	 * @return bool
	 */
	protected static function is_404( $response ) {
		return ! is_wp_error( $response ) && 404 === (int) wp_remote_retrieve_response_code( $response );
	}

	/**
	 * Turn a wp_remote_* result into data or a WP_Error.
	 *
	 * @param array|WP_Error $response Raw result.
	 * @param string         $url      For logging.
	 * @return array|WP_Error
	 */
	protected static function interpret( $response, $url ) {
		if ( is_wp_error( $response ) ) {
			ls_sso_log( 'transport error', array( 'url' => $url, 'error' => $response->get_error_message() ) );
			LS_SSO_Logger::log(
				'peer_request',
				array(
					'direction' => 'outbound',
					'peer'      => LS_SSO_Config::normalise_origin( $url ),
					'route'     => (string) wp_parse_url( $url, PHP_URL_PATH ),
					'status'    => 'failure',
					'detail'    => $response->get_error_message(),
				)
			);
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( $code < 200 || $code > 299 ) {
			ls_sso_log( 'remote refused', array( 'url' => $url, 'status' => $code ) );
			LS_SSO_Logger::log(
				'peer_request',
				array(
					'direction' => 'outbound',
					'peer'      => LS_SSO_Config::normalise_origin( $url ),
					'route'     => (string) wp_parse_url( $url, PHP_URL_PATH ),
					'status'    => 'failure',
					/* translators: %d: HTTP status code. */
					'detail'    => sprintf( 'HTTP %d', $code ),
				)
			);
			return new WP_Error( 'ls_sso_http_' . $code, 'Peer returned HTTP ' . $code, array( 'status' => $code ) );
		}

		if ( ! is_array( $body ) ) {
			return new WP_Error( 'ls_sso_bad_body', 'Peer returned a non-JSON body.' );
		}

		return $body;
	}
}

LS_SSO_Http::init();
