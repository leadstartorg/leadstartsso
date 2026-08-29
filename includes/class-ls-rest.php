<?php
/**
 * Inbound signed REST endpoints.
 *
 * Two routes only. Every additional route is additional attack surface on a
 * channel that, by design, bypasses WordPress's own authentication.
 *
 *   POST /leadstart-sso/v1/usermeta  — accept allowlisted user meta from a peer
 *   GET  /leadstart-sso/v1/orders    — serve a customer's order list (store only)
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * REST surface.
 */
class LS_SSO_Rest {

	const NAMESPACE_V1 = 'leadstart-sso/v1';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
		add_action( 'ls_sso_gc', array( 'LS_SSO_Signer', 'gc' ) );

		if ( ! wp_next_scheduled( 'ls_sso_gc' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'ls_sso_gc' );
		}
	}

	/**
	 * Register the routes.
	 *
	 * Note the `args` schemas. WordPress validates and sanitises against these
	 * before the callback runs, which is both a security control and the reason
	 * the callbacks below stay short.
	 *
	 * @return void
	 */
	public static function register_routes() {

		register_rest_route(
			self::NAMESPACE_V1,
			'/usermeta',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'receive_usermeta' ),
				'permission_callback' => array( 'LS_SSO_Signer', 'verify' ),
				'args'                => array(
					'subject' => array(
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
						'validate_callback' => function ( $value ) {
							return is_string( $value ) && '' !== trim( $value ) && strlen( $value ) <= 255;
						},
					),
					'meta'    => array(
						'required' => true,
						'type'     => 'object',
					),
				),
			)
		);

		// The order endpoint exists only where WooCommerce does. Registering it
		// unconditionally would advertise a route that always errors.
		if ( LS_SSO_Config::is_store() ) {
			register_rest_route(
				self::NAMESPACE_V1,
				'/orders',
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( __CLASS__, 'serve_orders' ),
					'permission_callback' => array( 'LS_SSO_Signer', 'verify' ),
					'args'                => array(
						'subject' => array(
							'required'          => true,
							'type'              => 'string',
							'sanitize_callback' => 'sanitize_text_field',
						),
						'limit'   => array(
							'required'          => false,
							'type'              => 'integer',
							'default'           => 10,
							'sanitize_callback' => 'absint',
							'validate_callback' => function ( $value ) {
								return $value >= 1 && $value <= 50;
							},
						),
					),
				)
			);
		}
	}

	/**
	 * Accept allowlisted user meta from a peer site.
	 *
	 * @param WP_REST_Request $request Inbound request.
	 * @return WP_REST_Response
	 */
	public static function receive_usermeta( WP_REST_Request $request ) {
		$subject = (string) $request->get_param( 'subject' );
		$meta    = (array) $request->get_param( 'meta' );

		$user = LS_SSO_Claims::user_by_subject( $subject );
		if ( ! $user ) {
			// The user has not signed in here yet. That is expected and not an
			// error: their next login pulls the same values from Auth0 claims.
			return new WP_REST_Response( array( 'ok' => true, 'applied' => 0, 'reason' => 'unknown_subject' ), 200 );
		}

		$allowed = LS_SSO_Config::meta_keys();
		$applied = 0;

		LS_SSO_Claims::without_broadcast(
			function () use ( $meta, $allowed, $user, &$applied ) {
				foreach ( $meta as $key => $value ) {
					$key = sanitize_key( (string) $key );

					// Strict allowlist membership. A prefix test such as
					// "starts with billing_" would let a peer write any key it
					// can name that happens to share the prefix.
					if ( ! in_array( $key, $allowed, true ) ) {
						continue;
					}
					if ( ! is_scalar( $value ) ) {
						continue;
					}

					update_user_meta( $user->ID, $key, sanitize_text_field( (string) $value ) );
					++$applied;
				}
			}
		);

		LS_SSO_Logger::log(
			'usermeta_received',
			array(
				'direction' => 'inbound',
				'peer'      => (string) $request->get_header( LS_SSO_Signer::HDR_ORIGIN ),
				'route'     => $request->get_route(),
				'user_id'   => $user->ID,
				'status'    => 'success',
				'detail'    => sprintf( '%d key(s) applied', $applied ),
			)
		);

		return new WP_REST_Response( array( 'ok' => true, 'applied' => $applied ), 200 );
	}

	/**
	 * Serve a customer's orders to a peer site.
	 *
	 * Returns a deliberately narrow projection: enough to render a history
	 * list, and nothing else. No line items, no addresses, no payment details,
	 * no customer note. If a satellite site is ever compromised, what it can
	 * pull is limited by what this method chose to include.
	 *
	 * @param WP_REST_Request $request Inbound request.
	 * @return WP_REST_Response
	 */
	public static function serve_orders( WP_REST_Request $request ) {
		$subject = (string) $request->get_param( 'subject' );
		$limit   = (int) $request->get_param( 'limit' );

		$user = LS_SSO_Claims::user_by_subject( $subject );
		if ( ! $user ) {
			return new WP_REST_Response( array( 'orders' => array() ), 200 );
		}

		// Query by customer_id, not billing_email. Email is mutable in Auth0
		// and guest orders can share one; customer_id is the actual link
		// between a WordPress user and their orders.
		$orders = wc_get_orders(
			array(
				'customer_id' => $user->ID,
				'limit'       => $limit,
				'orderby'     => 'date',
				'order'       => 'DESC',
				'type'        => 'shop_order',
			)
		);

		$out = array();
		foreach ( $orders as $order ) {
			if ( ! is_a( $order, 'WC_Order' ) ) {
				continue;
			}
			$created = $order->get_date_created();

			$out[] = array(
				'number'   => (string) $order->get_order_number(),
				'date'     => $created ? $created->date( DATE_ATOM ) : '',
				'status'   => (string) $order->get_status(),
				'status_label' => (string) wc_get_order_status_name( $order->get_status() ),
				// Pre-formatted on the store, where WooCommerce and the store's
				// currency settings actually exist. The satellite sites have
				// neither, so sending a raw float and a currency code would
				// require them to guess at formatting.
				'total_html' => wp_strip_all_tags( html_entity_decode( wc_price( $order->get_total(), array( 'currency' => $order->get_currency() ) ) ) ),
				'view_url' => (string) $order->get_view_order_url(),
			);
		}

		LS_SSO_Logger::log(
			'orders_served',
			array(
				'direction' => 'inbound',
				'peer'      => (string) $request->get_header( LS_SSO_Signer::HDR_ORIGIN ),
				'route'     => $request->get_route(),
				'user_id'   => $user->ID,
				'status'    => 'success',
				'detail'    => sprintf( '%d order(s)', count( $out ) ),
			)
		);

		return new WP_REST_Response( array( 'orders' => $out ), 200 );
	}
}
