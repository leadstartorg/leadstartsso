<?php
/**
 * Plugin Name:       Leadstart SSO
 * Plugin URI:        https://leadstart.org/leadstart-sso
 * Description:       Silent single sign-on, global single logout, and signed cross-site federation for separate WordPress installs sharing one OpenID Connect provider. Companion to OpenID Connect Generic.
 * Version:           1.4.1
 * Requires at least: 5.9
 * Requires PHP:      7.4
 * Author:            Leadstart Media, Inc.
 * Author URI:        https://leadstart.org
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       leadstart-sso
 * Domain Path:       /languages
 *
 * @package Leadstart_SSO
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT DO
 * ---------------------------------------------------------------------------
 * Auth0 is the single source of truth for identity. OpenID Connect Generic
 * (Daggerhart) handles the actual authentication on each site. This plugin
 * adds only the four things that plugin does not do:
 *
 *   1. SILENT SSO  — arriving at a second site logs you in without a click,
 *                    via `prompt=none` against the Auth0 session.
 *   2. GLOBAL LOGOUT — logging out anywhere clears all three sites and Auth0.
 *   3. CLAIMS MAPPING — Auth0 claims become WP roles and (on the store site)
 *                    WooCommerce billing/shipping meta.
 *   4. ORDER FEDERATION — the two non-store sites can display a customer's
 *                    order history, read-only, pulled from the store site.
 *
 * It does NOT sync passwords (Auth0 owns them), does NOT replicate user rows
 * (Daggerhart creates them from claims on demand), and does NOT replicate
 * WooCommerce orders (one store, one order table — read, never copy).
 *
 * ---------------------------------------------------------------------------
 * CONFIGURATION — wp-config.php constants, or the Settings tab when the host
 * does not allow editing that file. Constants always win.
 * ---------------------------------------------------------------------------
 *   define( 'LS_SSO_SECRET', '<64 hex chars, IDENTICAL on all three sites>' );
 *   define( 'LS_SSO_PEERS',  'https://leadstart.media,https://leadstart.studio' );
 *   define( 'LS_SSO_STORE',  'https://leadstart.org' );
 *
 * Optional:
 *   define( 'LS_SSO_ROLE_CLAIM', 'https://leadstart.org/roles' );
 *   define( 'LS_SSO_META_KEYS',  'ls_cohort,ls_program_track' );
 *   define( 'LS_SSO_SILENT',     true );      // silent SSO on/off
 *   define( 'LS_SSO_BLOCK_SILENT_ROLES', 'administrator' ); // never silent-login these
 *   define( 'LS_SSO_SILENT_MODE','js' );      // 'js' (cache-safe) or 'redirect'
 *   define( 'LS_SSO_DEBUG',      false );
 *
 * Generate the secret once:  php -r "echo bin2hex(random_bytes(32));"
 */

defined( 'ABSPATH' ) || exit;

/*
 * Double-load guard.
 *
 * This plugin can be installed either as a must-use plugin or as a regular one.
 * Installing it in BOTH places on the same site loads every class twice from
 * two different paths — require_once does not deduplicate across paths — which
 * is a fatal "cannot redeclare class" and a white screen, not a graceful
 * failure. That is an easy state to reach when moving from one install method
 * to the other and forgetting to remove the first copy.
 *
 * The copy that loads first wins. Must-use plugins load before regular ones, so
 * an older must-use copy would silently shadow a newer regular one; the admin
 * notice below says which file is actually running so that is visible rather
 * than mysterious.
 */
if ( defined( 'LS_SSO_VERSION' ) ) {
	if ( ! function_exists( 'ls_sso_duplicate_notice' ) ) {
		/**
		 * Warn that two copies of this plugin are installed.
		 *
		 * @return void
		 */
		function ls_sso_duplicate_notice() {
			if ( ! current_user_can( 'activate_plugins' ) ) {
				return;
			}
			echo '<div class="notice notice-warning"><p><strong>';
			esc_html_e( 'Leadstart SSO is installed twice.', 'leadstart-sso' );
			echo '</strong> ';
			printf(
				/* translators: 1: path of the copy that is running, 2: version. */
				esc_html__( 'The copy at %1$s (version %2$s) is the one running. Remove the other copy — most likely a leftover in mu-plugins or plugins — so future updates take effect.', 'leadstart-sso' ),
				'<code>' . esc_html( str_replace( ABSPATH, '', LS_SSO_FILE ) ) . '</code>',
				esc_html( LS_SSO_VERSION )
			);
			echo '</p></div>';
		}
		add_action( 'admin_notices', 'ls_sso_duplicate_notice' );
	}
	return;
}

define( 'LS_SSO_VERSION', '1.4.1' );
define( 'LS_SSO_FILE', __FILE__ );
define( 'LS_SSO_DIR', plugin_dir_path( __FILE__ ) );
define( 'LS_SSO_URL', plugin_dir_url( __FILE__ ) );

require_once LS_SSO_DIR . 'includes/class-ls-config.php';
require_once LS_SSO_DIR . 'includes/class-ls-logger.php';
require_once LS_SSO_DIR . 'includes/class-ls-signer.php';
require_once LS_SSO_DIR . 'includes/class-ls-http.php';
require_once LS_SSO_DIR . 'includes/class-ls-claims.php';
require_once LS_SSO_DIR . 'includes/class-ls-silent-login.php';
require_once LS_SSO_DIR . 'includes/class-ls-logout.php';
require_once LS_SSO_DIR . 'includes/class-ls-rest.php';
require_once LS_SSO_DIR . 'includes/class-ls-orders.php';
require_once LS_SSO_DIR . 'includes/class-ls-admin.php';

/**
 * Boot everything, but only once the host plugin is known to be present.
 *
 * We register on `plugins_loaded` rather than at file scope so that
 * `class_exists( 'OpenID_Connect_Generic' )` is a meaningful test. Running as a
 * must-use plugin, this file loads *before* regular plugins, so testing at file
 * scope would always fail.
 */
add_action(
	'init',
	function () {
		load_plugin_textdomain( 'leadstart-sso', false, dirname( plugin_basename( LS_SSO_FILE ) ) . '/languages' );
	}
);

add_action(
	'plugins_loaded',
	function () {

		// The REST surface is registered even when this site is not configured.
		// Otherwise an unconfigured peer answers 404, which is indistinguishable
		// from "the plugin is not installed there" and sends you looking in the
		// wrong place. Registered-but-unconfigured answers 503 instead, and the
		// signature check still refuses every request until a secret exists.
		LS_SSO_Rest::init();
		LS_SSO_Admin::init();

		// Configuration errors are surfaced in wp-admin rather than thrown, so
		// a mistyped constant never takes a public site down.
		if ( ! LS_SSO_Config::is_configured() ) {
			return;
		}

		// Federation and logout work without the OIDC plugin. Silent login and
		// claims mapping do not, so they are gated separately below.
		LS_SSO_Logger::init();
		LS_SSO_Orders::init();
		LS_SSO_Logout::init();

		if ( class_exists( 'OpenID_Connect_Generic' ) ) {
			LS_SSO_Claims::init();
			LS_SSO_Silent_Login::init();
		}
	},
	20
);

/**
 * Write a line to the plugin's own log. Never logs token values or the secret.
 *
 * @param string $message Human-readable message.
 * @param array  $context Extra key/value pairs.
 * @return void
 */
function ls_sso_log( $message, $context = array() ) {
	if ( ! LS_SSO_Config::debug() ) {
		return;
	}
	$line = '[leadstart-sso] ' . $message;
	if ( ! empty( $context ) ) {
		$line .= ' ' . wp_json_encode( $context );
	}
	error_log( $line ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
}
