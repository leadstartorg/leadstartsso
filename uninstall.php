<?php
/**
 * Uninstall routine.
 *
 * Runs only when the plugin is deleted through the WordPress admin — not on
 * deactivation, and never for a must-use install. If you run this as a must-use
 * plugin, removing the folder leaves the table and options behind; call
 * LS_SSO_Logger::drop() manually or via WP-CLI if you want them gone.
 *
 * Note what is NOT removed: nothing in wp-config.php. The shared secret and peer
 * list are file constants and are not this file's to touch.
 *
 * @package Leadstart_SSO
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

require_once __DIR__ . '/includes/class-ls-logger.php';

global $wpdb;

// Activity log table and its schema marker.
LS_SSO_Logger::drop();

// Settings stored via the admin screen (constants in wp-config.php are not
// ours to touch and are left exactly as they are).
foreach ( array( 'ls_sso_secret', 'ls_sso_peers', 'ls_sso_store', 'ls_sso_role_claim', 'ls_sso_meta_keys', 'ls_sso_block_silent_roles', 'ls_sso_silent_mode' ) as $option ) {
	delete_option( $option );
}

// Scheduled jobs.
foreach ( array( 'ls_sso_gc', 'ls_sso_purge_log', 'ls_sso_dispatch_worker' ) as $hook ) {
	wp_clear_scheduled_hook( $hook );
}

// Cached JWKS.
delete_transient( 'ls_sso_jwks' );

// Spent-nonce and replayed-jti rows. These are transient by nature and expire
// on their own, but a deleted plugin should not leave hundreds of them behind.
// phpcs:disable WordPress.DB.DirectDatabaseQuery
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( 'ls_sso_nonce_' ) . '%',
		$wpdb->esc_like( 'ls_sso_jti_' ) . '%'
	)
);

// Per-user cached order lists.
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( '_transient_ls_sso_orders_' ) . '%',
		$wpdb->esc_like( '_transient_timeout_ls_sso_orders_' ) . '%'
	)
);
// phpcs:enable WordPress.DB.DirectDatabaseQuery
