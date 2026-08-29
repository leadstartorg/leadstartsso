<?php
/**
 * Auth0 claims -> WordPress user, roles, and (store site only) WooCommerce meta.
 *
 * ---------------------------------------------------------------------------
 * THE HOOK NAMES
 * ---------------------------------------------------------------------------
 * `openid-connect-generic-user-login-import` does not exist in OpenID Connect
 * Generic 3.11.3. Code attached to it never runs, and never errors — it simply
 * does nothing, forever. The real hooks, read from the plugin source, are:
 *
 *   openid-connect-generic-user-create                    ( WP_User, array $claim )
 *   openid-connect-generic-update-user-using-current-claim( WP_User, array $claim )
 *   openid-connect-generic-user-logged-in                 ( WP_User )
 *
 * The first fires once, when the local account is created from claims. The
 * second fires on every subsequent login. Mapping needs both: the first alone
 * means a user whose address changes in Auth0 keeps the stale copy forever.
 *
 * ---------------------------------------------------------------------------
 * IDENTITY: SUBJECT, NOT EMAIL
 * ---------------------------------------------------------------------------
 * Every cross-site lookup keys on the OIDC subject (`sub`), not the email
 * address. Email in Auth0 is mutable and, on some connections, not unique.
 * Matching on it means that a customer who changes their email becomes a
 * different person to the other two sites, and that an attacker who can set an
 * email address on one site can address another site's user record.
 *
 * OpenID Connect Generic already stores `sub` as a *global* user option
 * (`openid-connect-generic-subject-identity`), which is the value we reuse.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Claim mapping.
 */
class LS_SSO_Claims {

	/**
	 * The user option OpenID Connect Generic writes the subject to.
	 */
	const SUBJECT_OPTION = 'openid-connect-generic-subject-identity';

	/**
	 * Guard flag: true while we are applying a change that arrived from a peer.
	 *
	 * Without this, applying a remote update fires the local save hooks, which
	 * broadcast the change straight back out. Two sites then bounce the same
	 * payload between them until something gives.
	 *
	 * @var bool
	 */
	protected static $applying_remote = false;

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'openid-connect-generic-user-create', array( __CLASS__, 'on_claim' ), 10, 2 );
		add_action( 'openid-connect-generic-update-user-using-current-claim', array( __CLASS__, 'on_claim' ), 10, 2 );

		// Outbound profile propagation runs only where WooCommerce actually is.
		// On the two non-store sites these hooks would never fire anyway; being
		// explicit documents the intent rather than relying on that accident.
		if ( LS_SSO_Config::is_store() ) {
			add_action( 'woocommerce_save_account_details', array( __CLASS__, 'on_profile_saved' ), 10, 1 );
			add_action( 'woocommerce_customer_save_address', array( __CLASS__, 'on_profile_saved' ), 10, 1 );
			add_action( 'woocommerce_checkout_update_customer', array( __CLASS__, 'on_checkout_customer' ), 10, 2 );
		}
	}

	/**
	 * Whether a remote-originated write is currently in progress.
	 *
	 * @return bool
	 */
	public static function is_applying_remote() {
		return self::$applying_remote;
	}

	/**
	 * Run a callback with the loop guard raised.
	 *
	 * @param callable $callback Work to perform.
	 * @return mixed
	 */
	public static function without_broadcast( callable $callback ) {
		$previous              = self::$applying_remote;
		self::$applying_remote = true;
		try {
			return $callback();
		} finally {
			self::$applying_remote = $previous;
		}
	}

	/**
	 * Apply Auth0 claims to a local user.
	 *
	 * @param WP_User $user  The local user.
	 * @param array   $claim The claim set from Auth0.
	 * @return void
	 */
	public static function on_claim( $user, $claim ) {
		if ( ! $user instanceof WP_User || ! is_array( $claim ) ) {
			return;
		}

		self::without_broadcast(
			function () use ( $user, $claim ) {
				self::apply_roles( $user, $claim );
				if ( LS_SSO_Config::is_store() ) {
					self::apply_woocommerce_profile( $user, $claim );
				}
				self::apply_allowlisted_meta( $user, $claim );
			}
		);

		/**
		 * Fires after Leadstart SSO has mapped a claim set onto a user.
		 *
		 * @param WP_User $user  The user.
		 * @param array   $claim The claim set.
		 */
		do_action( 'ls_sso_claims_applied', $user, $claim );
	}

	/**
	 * Map an Auth0 roles claim onto WordPress roles.
	 *
	 * Roles live in Auth0 and are recomputed on every login, which means role
	 * changes propagate to all three sites the next time the user signs in —
	 * with no cross-site API call at all. Administrators are never granted or
	 * revoked this way: an IdP misconfiguration should not be able to hand out
	 * or take away admin on a live site.
	 *
	 * @param WP_User $user  The user.
	 * @param array   $claim Claim set.
	 * @return void
	 */
	protected static function apply_roles( WP_User $user, array $claim ) {
		// Existing administrators are never re-roled from claims. An IdP
		// misconfiguration should not be able to demote the person who has to
		// log in and fix it.
		if ( user_can( $user, 'manage_options' ) ) {
			return;
		}

		$claim_key = LS_SSO_Config::role_claim();

		$incoming = ( '' !== $claim_key && isset( $claim[ $claim_key ] ) )
			? (array) $claim[ $claim_key ]
			: array();

		/**
		 * Map identity-provider role strings to WordPress role slugs.
		 *
		 * This filter runs on every SSO login even when no role claim is
		 * configured — $incoming is simply empty in that case. That is
		 * deliberate: it lets a site force a default role (say, `customer`
		 * rather than the site's default_role) without having to set up a
		 * namespaced claim at the identity provider first.
		 *
		 * Returning an empty array leaves the user's existing roles untouched,
		 * which for a brand new user means whatever wp_insert_user() assigned
		 * from Settings > General > New User Default Role.
		 *
		 * @param array   $roles    Resolved WP role slugs. Empty by default.
		 * @param array   $incoming Raw claim values; empty if no role claim.
		 * @param WP_User $user     The user being logged in.
		 */
		$roles = apply_filters( 'ls_sso_map_roles', array(), $incoming, $user );

		$roles = array_values(
			array_filter(
				array_map( 'sanitize_key', (array) $roles ),
				function ( $role ) {
					return 'administrator' !== $role && ! empty( get_role( $role ) );
				}
			)
		);

		if ( empty( $roles ) ) {
			return;
		}

		$user->set_role( array_shift( $roles ) );
		foreach ( $roles as $extra ) {
			$user->add_role( $extra );
		}
	}

	/**
	 * Map claims onto WooCommerce billing and shipping fields.
	 *
	 * Two departures from the usual snippet doing the rounds:
	 *
	 *  - Shipping is not blindly overwritten from billing. A customer who ships
	 *    to a different address than they bill to has that overwritten on every
	 *    single login. Shipping is filled only where it is currently empty.
	 *  - Locally entered values win over claim values. The customer typing an
	 *    address into checkout is a stronger signal than a stale Auth0 profile.
	 *
	 * @param WP_User $user  The user.
	 * @param array   $claim Claim set.
	 * @return void
	 */
	protected static function apply_woocommerce_profile( WP_User $user, array $claim ) {
		$address = isset( $claim['address'] ) && is_array( $claim['address'] ) ? $claim['address'] : array();

		$map = array(
			'billing_first_name' => $claim['given_name'] ?? '',
			'billing_last_name'  => $claim['family_name'] ?? '',
			'billing_email'      => $claim['email'] ?? '',
			'billing_phone'      => $claim['phone_number'] ?? '',
			'billing_address_1'  => $address['street_address'] ?? '',
			'billing_city'       => $address['locality'] ?? '',
			'billing_state'      => $address['region'] ?? '',
			'billing_postcode'   => $address['postal_code'] ?? '',
			'billing_country'    => $address['country'] ?? '',
		);

		foreach ( $map as $key => $value ) {
			$value = trim( (string) $value );
			if ( '' === $value ) {
				continue;
			}

			$value = ( 'billing_email' === $key )
				? sanitize_email( $value )
				: sanitize_text_field( $value );

			if ( '' === $value ) {
				continue;
			}

			// Do not clobber something the customer entered here.
			$existing = get_user_meta( $user->ID, $key, true );
			if ( '' === $existing ) {
				update_user_meta( $user->ID, $key, $value );
			}

			// Seed shipping from billing only when shipping is genuinely blank.
			$shipping_key = str_replace( 'billing_', 'shipping_', $key );
			if ( 'shipping_email' === $shipping_key ) {
				continue; // WooCommerce has no shipping_email field.
			}
			if ( '' === get_user_meta( $user->ID, $shipping_key, true ) ) {
				update_user_meta( $user->ID, $shipping_key, $value );
			}
		}
	}

	/**
	 * Copy allowlisted custom claims into user meta.
	 *
	 * @param WP_User $user  The user.
	 * @param array   $claim Claim set.
	 * @return void
	 */
	protected static function apply_allowlisted_meta( WP_User $user, array $claim ) {
		foreach ( LS_SSO_Config::meta_keys() as $key ) {
			if ( ! isset( $claim[ $key ] ) ) {
				continue;
			}
			$value = $claim[ $key ];
			$value = is_scalar( $value ) ? sanitize_text_field( (string) $value ) : wp_json_encode( $value );
			update_user_meta( $user->ID, $key, $value );
		}
	}

	/**
	 * WooCommerce profile save -> queue an allowlisted push to the peers.
	 *
	 * Only the keys in LS_SSO_META_KEYS travel. Billing and shipping addresses
	 * deliberately do not: WooCommerce runs on one site, so the other two have
	 * no checkout to prefill and no reason to hold a customer's home address.
	 * Not copying it is the whole of the GDPR data-minimisation story here.
	 *
	 * @param int $user_id User whose profile was saved.
	 * @return void
	 */
	public static function on_profile_saved( $user_id ) {
		$user_id = (int) $user_id;
		if ( ! $user_id || self::is_applying_remote() ) {
			return;
		}

		$keys = LS_SSO_Config::meta_keys();
		if ( empty( $keys ) ) {
			return;
		}

		$subject = self::subject_for( $user_id );
		if ( '' === $subject ) {
			return; // Not an SSO user; nothing the peers can match on.
		}

		$meta = array();
		foreach ( $keys as $key ) {
			$meta[ $key ] = (string) get_user_meta( $user_id, $key, true );
		}

		LS_SSO_Http::queue(
			'/leadstart-sso/v1/usermeta',
			array(
				'subject' => $subject,
				'meta'    => $meta,
			)
		);
	}

	/**
	 * Checkout variant of the above.
	 *
	 * @param WC_Customer $customer Customer object.
	 * @param array       $data     Posted checkout data.
	 * @return void
	 */
	public static function on_checkout_customer( $customer, $data ) {
		unset( $data );
		if ( is_object( $customer ) && method_exists( $customer, 'get_id' ) && $customer->get_id() ) {
			self::on_profile_saved( $customer->get_id() );
		}
	}

	/**
	 * Read a user's OIDC subject.
	 *
	 * @param int $user_id User ID.
	 * @return string Empty string when the user has never signed in via Auth0.
	 */
	public static function subject_for( $user_id ) {
		$subject = get_user_option( self::SUBJECT_OPTION, $user_id );
		return is_string( $subject ) ? $subject : '';
	}

	/**
	 * Find a local user by OIDC subject.
	 *
	 * Checks the global option key first and the blog-prefixed key second,
	 * matching the lookup OpenID Connect Generic itself performs.
	 *
	 * @param string $subject OIDC `sub`.
	 * @return WP_User|null
	 */
	public static function user_by_subject( $subject ) {
		global $wpdb;

		$subject = (string) $subject;
		if ( '' === $subject ) {
			return null;
		}

		$query = new WP_User_Query(
			array(
				'number'     => 1,
				'fields'     => 'ID',
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
				'meta_query' => array(
					'relation' => 'OR',
					array(
						'key'   => self::SUBJECT_OPTION,
						'value' => $subject,
					),
					array(
						'key'   => $wpdb->get_blog_prefix() . self::SUBJECT_OPTION,
						'value' => $subject,
					),
				),
			)
		);

		$ids = $query->get_results();
		if ( empty( $ids ) ) {
			return null;
		}

		$user = get_user_by( 'id', (int) $ids[0] );
		return $user instanceof WP_User ? $user : null;
	}
}
