<?php
/**
 * Order history on the two non-store sites.
 *
 * ---------------------------------------------------------------------------
 * THE DIRECTION OF THIS FEED
 * ---------------------------------------------------------------------------
 * WooCommerce runs on exactly one of the three sites. So there is nothing to
 * "federate" *into* the store — the store already has every order. What the
 * other two sites lack is any way to show a signed-in customer their history.
 *
 * The flow is therefore one-way: satellite asks the store, store answers,
 * satellite renders. No order data is ever written to a satellite database.
 * Nothing is replicated, so nothing can drift, and a customer's order history
 * has exactly one authoritative copy.
 *
 * Rendering is via a shortcode, `[leadstart_orders]`, rather than by hijacking
 * WooCommerce's My Account template — which does not exist on these sites.
 *
 * ---------------------------------------------------------------------------
 * ON `Requests::request_multiple()`
 * ---------------------------------------------------------------------------
 * The parallel-request class in WordPress was moved to the `WpOrg\Requests`
 * namespace in WordPress 6.2. `Requests_Response` no longer exists as a real
 * class, so `$response instanceof Requests_Response` is false for every
 * response on any current WordPress — which makes an order list that silently
 * renders empty, forever, with no error anywhere.
 *
 * We fetch from one origin, so parallelism buys nothing anyway. A single
 * `wp_remote_get()` with a short timeout and a cached result is both correct
 * and faster in the common case.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Read-only order history for satellite sites.
 */
class LS_SSO_Orders {

	/**
	 * How long a fetched order list is cached per user.
	 */
	const CACHE_TTL = 300;

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		// Satellites consume; the store has its own My Account page already.
		if ( LS_SSO_Config::is_store() ) {
			return;
		}

		add_shortcode( 'leadstart_orders', array( __CLASS__, 'render' ) );
	}

	/**
	 * Fetch a user's orders from the store site.
	 *
	 * @param int $user_id User to fetch for.
	 * @return array<int,array> Possibly empty.
	 */
	public static function fetch( $user_id ) {
		$store = LS_SSO_Config::store_origin();
		if ( '' === $store || $store === LS_SSO_Config::self_origin() ) {
			return array();
		}

		$subject = LS_SSO_Claims::subject_for( $user_id );
		if ( '' === $subject ) {
			return array();
		}

		$cache_key = 'ls_sso_orders_' . md5( $subject );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		// Short timeout: this runs while a visitor waits for a page. If the
		// store is slow, an empty list now beats a hung request.
		$result = LS_SSO_Http::get(
			$store,
			'/leadstart-sso/v1/orders',
			array(
				'subject' => $subject,
				'limit'   => 10,
			),
			4
		);

		if ( is_wp_error( $result ) || ! isset( $result['orders'] ) || ! is_array( $result['orders'] ) ) {
			// Cache the failure briefly too, so a store outage does not mean a
			// four-second wait on every page view for every customer.
			set_transient( $cache_key, array(), 60 );
			return array();
		}

		set_transient( $cache_key, $result['orders'], self::CACHE_TTL );

		return $result['orders'];
	}

	/**
	 * Shortcode output.
	 *
	 * Every interpolated value is escaped at the point of output. The data
	 * arrives over the network from another host: even though that host is ours
	 * and the response was signed, treating its strings as trusted markup is
	 * how one compromised site becomes three.
	 *
	 * @param array $atts Shortcode attributes.
	 * @return string
	 */
	public static function render( $atts ) {
		$atts = shortcode_atts(
			array(
				'empty' => __( 'No orders yet.', 'leadstart-sso' ),
			),
			$atts,
			'leadstart_orders'
		);

		if ( ! is_user_logged_in() ) {
			return '';
		}

		$orders = self::fetch( get_current_user_id() );

		if ( empty( $orders ) ) {
			return '<p class="ls-orders-empty">' . esc_html( $atts['empty'] ) . '</p>';
		}

		$store_label = wp_parse_url( LS_SSO_Config::store_origin(), PHP_URL_HOST );

		ob_start();
		?>
		<table class="ls-orders">
			<caption>
				<?php
				printf(
					/* translators: %s: hostname of the store site. */
					esc_html__( 'Your orders from %s', 'leadstart-sso' ),
					esc_html( $store_label )
				);
				?>
			</caption>
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Order', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Date', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Total', 'leadstart-sso' ); ?></th>
					<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'leadstart-sso' ); ?></span></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $orders as $order ) : ?>
				<?php
				$number    = isset( $order['number'] ) ? (string) $order['number'] : '';
				$date_raw  = isset( $order['date'] ) ? (string) $order['date'] : '';
				$timestamp = $date_raw ? strtotime( $date_raw ) : false;
				$status    = isset( $order['status_label'] ) ? (string) $order['status_label'] : '';
				$total     = isset( $order['total_html'] ) ? (string) $order['total_html'] : '';
				$view_url  = isset( $order['view_url'] ) ? (string) $order['view_url'] : '';

				// Only ever link back to the store we asked.
				if ( '' !== $view_url && ! LS_SSO_Config::is_known_origin( $view_url ) ) {
					$view_url = '';
				}
				?>
				<tr>
					<th scope="row">#<?php echo esc_html( $number ); ?></th>
					<td>
						<?php
						echo $timestamp
							? esc_html( date_i18n( get_option( 'date_format' ), $timestamp ) )
							: '&mdash;';
						?>
					</td>
					<td><?php echo esc_html( $status ); ?></td>
					<td><?php echo esc_html( $total ); ?></td>
					<td>
						<?php if ( '' !== $view_url ) : ?>
							<a href="<?php echo esc_url( $view_url ); ?>" rel="noopener">
								<?php esc_html_e( 'View', 'leadstart-sso' ); ?>
							</a>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Drop a user's cached order list.
	 *
	 * @param string $subject OIDC subject.
	 * @return void
	 */
	public static function flush( $subject ) {
		delete_transient( 'ls_sso_orders_' . md5( (string) $subject ) );
	}
}
