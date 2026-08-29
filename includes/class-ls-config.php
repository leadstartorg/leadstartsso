<?php
/**
 * Configuration reader.
 *
 * ---------------------------------------------------------------------------
 * CONSTANT FIRST, OPTION AS FALLBACK
 * ---------------------------------------------------------------------------
 * A wp-config.php constant is the better place for this configuration, and
 * especially for the shared secret: it stays out of database backups and
 * exports, out of reach of any options-disclosure bug, and cannot be changed by
 * an administrator who does not also have file access.
 *
 * But requiring it makes the plugin unusable on a large slice of managed
 * hosting. WordPress.com, for one, grants SFTP only on its Business and
 * Commerce plans, while plugin installation is available on every paid plan —
 * so a site can perfectly well run this plugin and still have no way to edit
 * wp-config.php. A constants-only design does not protect that site; it just
 * locks it out.
 *
 * So: every setting is read from its constant when one is defined, and from the
 * options table otherwise. Defining the constant always wins, and the admin
 * screen shows which source each value came from. The secret stored as an
 * option is never rendered back to the screen — only a short fingerprint, which
 * is enough to check that three sites agree without revealing the value.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Static accessor for plugin configuration.
 */
class LS_SSO_Config {

	/**
	 * Cached, normalised peer list.
	 *
	 * @var array<int,string>|null
	 */
	protected static $peers = null;

	/**
	 * Option names, keyed by the constant they fall back from.
	 */
	const OPTIONS = array(
		'LS_SSO_SECRET'              => 'ls_sso_secret',
		'LS_SSO_PEERS'               => 'ls_sso_peers',
		'LS_SSO_STORE'               => 'ls_sso_store',
		'LS_SSO_ROLE_CLAIM'          => 'ls_sso_role_claim',
		'LS_SSO_META_KEYS'           => 'ls_sso_meta_keys',
		'LS_SSO_BLOCK_SILENT_ROLES'  => 'ls_sso_block_silent_roles',
		'LS_SSO_SILENT_MODE'         => 'ls_sso_silent_mode',
	);

	/**
	 * Resolve one setting: constant if defined, else option, else default.
	 *
	 * @param string $constant Constant name.
	 * @param string $fallback Value when neither is set.
	 * @return string
	 */
	protected static function get( $constant, $fallback = '' ) {
		if ( defined( $constant ) ) {
			return (string) constant( $constant );
		}

		$option = isset( self::OPTIONS[ $constant ] ) ? self::OPTIONS[ $constant ] : '';
		if ( '' === $option ) {
			return $fallback;
		}

		$stored = get_option( $option, null );

		return ( null === $stored || '' === $stored ) ? $fallback : (string) $stored;
	}

	/**
	 * Where a setting's value came from: 'constant', 'option', or 'default'.
	 *
	 * Shown on the status screen so a site with three different configuration
	 * sources is legible rather than mysterious.
	 *
	 * @param string $constant Constant name.
	 * @return string
	 */
	public static function source_of( $constant ) {
		if ( defined( $constant ) ) {
			return 'constant';
		}
		$option = isset( self::OPTIONS[ $constant ] ) ? self::OPTIONS[ $constant ] : '';
		if ( '' !== $option ) {
			$stored = get_option( $option, null );
			if ( null !== $stored && '' !== $stored ) {
				return 'option';
			}
		}
		return 'default';
	}

	/**
	 * Persist a setting to the options table.
	 *
	 * Refuses when a constant of the same name is defined: silently storing a
	 * value that the constant then overrides is how an administrator ends up
	 * certain they changed something that never took effect.
	 *
	 * @param string $constant Constant name.
	 * @param string $value    New value; empty string deletes the option.
	 * @return bool True when stored or cleared.
	 */
	public static function save( $constant, $value ) {
		if ( defined( $constant ) || ! isset( self::OPTIONS[ $constant ] ) ) {
			return false;
		}

		$option      = self::OPTIONS[ $constant ];
		$existing    = get_option( $option, false );
		self::$peers = null; // Bust the peer cache.

		if ( '' === $value ) {
			delete_option( $option );
			return false !== $existing;
		}

		// Report success when the setting already holds this exact value.
		// update_option() returns false for a no-op write, which would
		// otherwise be reported to the user as "nothing was saved".
		if ( (string) $existing === $value ) {
			return true;
		}

		// autoload 'no': the secret in particular should not ride along in the
		// bulk option load on every single request.
		if ( false === $existing ) {
			return add_option( $option, $value, '', 'no' );
		}
		return update_option( $option, $value, false );
	}

	/**
	 * A short, non-reversible fingerprint of the shared secret.
	 *
	 * Lets an administrator confirm that every site holds the same secret
	 * without the value ever being displayed or transmitted.
	 *
	 * @return string Empty when no secret is set.
	 */
	public static function secret_fingerprint() {
		$secret = self::secret();
		return '' === $secret ? '' : substr( hash( 'sha256', $secret ), 0, 8 );
	}

	/**
	 * The shared HMAC secret.
	 *
	 * @return string Empty string when unset.
	 */
	public static function secret() {
		return self::get( 'LS_SSO_SECRET' );
	}

	/**
	 * The other two sites, as scheme+host origins with no trailing slash.
	 *
	 * @return array<int,string>
	 */
	public static function peers() {
		if ( null !== self::$peers ) {
			return self::$peers;
		}

		$raw = self::get( 'LS_SSO_PEERS' );
		$out = array();

		foreach ( explode( ',', $raw ) as $candidate ) {
			$origin = self::normalise_origin( $candidate );
			// Never treat ourselves as a peer, however the constant is written.
			if ( '' !== $origin && $origin !== self::self_origin() ) {
				$out[] = $origin;
			}
		}

		self::$peers = array_values( array_unique( $out ) );
		return self::$peers;
	}

	/**
	 * Origin of the site that runs WooCommerce.
	 *
	 * The same value is configured on all three sites; each site works out
	 * whether it is the store by comparing against its own origin.
	 *
	 * @return string
	 */
	public static function store_origin() {
		return self::normalise_origin( self::get( 'LS_SSO_STORE' ) );
	}

	/**
	 * Whether this site is the store.
	 *
	 * Tests the constant first and WooCommerce's presence second, so a
	 * misconfigured constant cannot make a satellite try to answer order
	 * queries it has no tables for.
	 *
	 * @return bool
	 */
	public static function is_store() {
		return self::store_origin() === self::self_origin() && class_exists( 'WooCommerce' );
	}

	/**
	 * This site's own origin, normalised the same way peers are.
	 *
	 * @return string
	 */
	public static function self_origin() {
		return self::normalise_origin( home_url( '/' ) );
	}

	/**
	 * Every origin in the federation, including this one.
	 *
	 * @return array<int,string>
	 */
	public static function all_origins() {
		$all = self::peers();
		$all[] = self::self_origin();
		$store = self::store_origin();
		if ( '' !== $store ) {
			$all[] = $store;
		}
		return array_values( array_unique( array_filter( $all ) ) );
	}

	/**
	 * The Auth0 claim carrying the user's roles, if role mapping is in use.
	 *
	 * @return string
	 */
	public static function role_claim() {
		return self::get( 'LS_SSO_ROLE_CLAIM' );
	}

	/**
	 * Allowlisted user meta keys eligible for cross-site push.
	 *
	 * An allowlist, never a prefix match: a prefix rule such as "anything
	 * starting with billing_" is exactly how a remote site ends up able to
	 * write keys you never intended.
	 *
	 * @return array<int,string>
	 */
	public static function meta_keys() {
		$raw = self::get( 'LS_SSO_META_KEYS' );
		$out = array();
		foreach ( explode( ',', $raw ) as $key ) {
			$key = sanitize_key( trim( $key ) );
			if ( '' !== $key ) {
				$out[] = $key;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Whether silent SSO probing is enabled.
	 *
	 * @return bool
	 */
	public static function silent_enabled() {
		return defined( 'LS_SSO_SILENT' ) ? (bool) LS_SSO_SILENT : true;
	}

	/**
	 * Silent SSO transport: 'js' or 'redirect'.
	 *
	 * 'js' is the default because these sites sit behind an edge cache. A
	 * server-side 302 issued from a cacheable page can be stored by that cache
	 * and then served to every subsequent visitor, which turns one probe into a
	 * site-wide redirect loop. The JS transport cannot be cached into that
	 * failure because the decision happens in the visitor's browser.
	 *
	 * @return string
	 */
	public static function silent_mode() {
		$mode = self::get( 'LS_SSO_SILENT_MODE', 'js' );
		return in_array( $mode, array( 'js', 'redirect' ), true ) ? $mode : 'js';
	}

	/**
	 * Roles for which a silent, non-interactive session is refused.
	 *
	 * @return array<int,string>
	 */
	public static function blocked_silent_roles() {
		$raw = self::get( 'LS_SSO_BLOCK_SILENT_ROLES', 'administrator' );

		$roles = array();
		foreach ( explode( ',', $raw ) as $role ) {
			$role = sanitize_key( trim( $role ) );
			if ( '' !== $role ) {
				$roles[] = $role;
			}
		}

		/**
		 * Filter the roles refused a silently-established session.
		 *
		 * @param array $roles Role slugs.
		 */
		return (array) apply_filters( 'ls_sso_block_silent_roles', array_values( array_unique( $roles ) ) );
	}

	/**
	 * Debug logging flag.
	 *
	 * @return bool
	 */
	public static function debug() {
		return defined( 'LS_SSO_DEBUG' ) && LS_SSO_DEBUG;
	}

	/**
	 * Whether the minimum configuration is present and sane.
	 *
	 * @return bool
	 */
	public static function is_configured() {
		return strlen( self::secret() ) >= 32 && ! empty( self::peers() );
	}

	/**
	 * Reduce a URL to "scheme://host[:port]", lowercased, no trailing slash.
	 *
	 * @param string $url Any URL or origin.
	 * @return string Empty string if unparseable or not http(s).
	 */
	public static function normalise_origin( $url ) {
		$url = trim( (string) $url );
		if ( '' === $url ) {
			return '';
		}

		$parts = wp_parse_url( $url );
		if ( empty( $parts['host'] ) ) {
			return '';
		}

		$scheme = isset( $parts['scheme'] ) ? strtolower( $parts['scheme'] ) : 'https';
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}

		$origin = $scheme . '://' . strtolower( $parts['host'] );
		if ( ! empty( $parts['port'] ) ) {
			$origin .= ':' . (int) $parts['port'];
		}
		return $origin;
	}

	/**
	 * Whether a URL belongs to one of our federated origins.
	 *
	 * Used everywhere a redirect target arrives from outside. Compares whole
	 * normalised origins, never `str_contains`, so `https://leadstart.org.evil.com`
	 * cannot pass as `https://leadstart.org`.
	 *
	 * @param string $url URL to test.
	 * @return bool
	 */
	public static function is_known_origin( $url ) {
		$origin = self::normalise_origin( $url );
		return '' !== $origin && in_array( $origin, self::all_origins(), true );
	}
}
