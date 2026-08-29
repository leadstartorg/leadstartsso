<?php
/**
 * Activity log.
 *
 * ---------------------------------------------------------------------------
 * THREE CORRECTIONS TO THE OBVIOUS IMPLEMENTATION
 * ---------------------------------------------------------------------------
 *
 * 1. THE LOG IS NOT GATED ON DEBUG MODE.
 *    An audit log that only writes when a debug constant is true is empty in
 *    production, which is the only place you need it. Worse than having no
 *    table at all: the table exists, the admin screen renders, and the absence
 *    of rows reads as "nothing happened" rather than "nothing was recorded".
 *    Debug logging (verbose, to error_log) and audit logging (structured, to a
 *    table, always on) are different features. This is the second one.
 *
 * 2. THE TABLE IS NOT CREATED BY register_activation_hook().
 *    That hook never fires for a must-use plugin — mu-plugins are not
 *    "activated". A plugin installed to mu-plugins would create no table, and
 *    every insert would then fail silently against a table that does not exist.
 *    We run a version-checked migration on load instead, which works whether
 *    the plugin is must-use, network-activated, or activated normally.
 *
 * 3. $wpdb->prepare() IS NEVER CALLED WITH ZERO PLACEHOLDERS.
 *    prepare() with no placeholders triggers _doing_it_wrong() and returns an
 *    empty string, so the query silently returns nothing. A log screen whose
 *    filters are all empty — i.e. the default view — is exactly that case. The
 *    read path below builds its placeholder list and arguments together and
 *    skips prepare() entirely when there is nothing to bind.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Structured activity log.
 */
class LS_SSO_Logger {

	/**
	 * Table suffix, appended to $wpdb->prefix.
	 */
	const TABLE = 'ls_sso_activity';

	/**
	 * Option storing the installed schema version.
	 */
	const SCHEMA_OPTION = 'ls_sso_schema_version';

	/**
	 * Current schema version. Bump to trigger a migration.
	 */
	const SCHEMA_VERSION = 1;

	/**
	 * Default retention in days.
	 */
	const RETENTION_DAYS = 30;

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		// Called directly, not hooked. init() itself runs from a plugins_loaded
		// callback, so registering another plugins_loaded callback at a LOWER
		// priority registers it for a moment that has already passed —
		// WordPress skips priorities below the one currently executing, and the
		// migration would never run. The table would never exist, is_ready()
		// would always be false, and every log() call would quietly do nothing.
		self::maybe_migrate();

		add_action( 'ls_sso_purge_log', array( __CLASS__, 'purge' ) );

		if ( ! wp_next_scheduled( 'ls_sso_purge_log' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'ls_sso_purge_log' );
		}
	}

	/**
	 * Fully-qualified table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE;
	}

	/**
	 * Create or upgrade the table if the stored schema version is behind.
	 *
	 * @return void
	 */
	public static function maybe_migrate() {
		if ( (int) get_option( self::SCHEMA_OPTION ) === self::SCHEMA_VERSION ) {
			return;
		}

		global $wpdb;

		$table   = self::table();
		$collate = $wpdb->get_charset_collate();

		// No ENUM: adding a value to an ENUM later is a table rebuild, and a
		// value outside the set is silently coerced to '' on insert under a
		// non-strict SQL mode. A short VARCHAR validated in PHP is safer.
		$sql = "CREATE TABLE {$table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			logged_at DATETIME NOT NULL,
			event VARCHAR(50) NOT NULL DEFAULT '',
			direction VARCHAR(10) NOT NULL DEFAULT 'outbound',
			peer VARCHAR(191) NOT NULL DEFAULT '',
			route VARCHAR(191) NOT NULL DEFAULT '',
			user_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
			status VARCHAR(10) NOT NULL DEFAULT 'success',
			detail TEXT NULL,
			PRIMARY KEY (id),
			KEY logged_at (logged_at),
			KEY event (event),
			KEY status (status),
			KEY user_id (user_id)
		) {$collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Whether the log table is present and usable.
	 *
	 * @return bool
	 */
	public static function is_ready() {
		return (int) get_option( self::SCHEMA_OPTION ) === self::SCHEMA_VERSION;
	}

	/**
	 * Record an event.
	 *
	 * Deliberately records no request bodies, no meta values, no tokens and no
	 * signatures. An audit log that copies the payload becomes a second,
	 * less-guarded store of the same personal data — and one that survives long
	 * after the request did.
	 *
	 * @param string $event Short event slug, e.g. 'usermeta.received'.
	 * @param array  $args  Optional fields: direction, peer, route, user_id,
	 *                      status, detail.
	 * @return void
	 */
	public static function log( $event, array $args = array() ) {
		if ( ! self::is_ready() ) {
			return;
		}

		global $wpdb;

		$args = wp_parse_args(
			$args,
			array(
				'direction' => 'outbound',
				'peer'      => '',
				'route'     => '',
				'user_id'   => 0,
				'status'    => 'success',
				'detail'    => '',
			)
		);

		$direction = in_array( $args['direction'], array( 'inbound', 'outbound' ), true )
			? $args['direction']
			: 'outbound';

		$status = in_array( $args['status'], array( 'success', 'failure' ), true )
			? $args['status']
			: 'success';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->insert(
			self::table(),
			array(
				'logged_at' => current_time( 'mysql', true ),
				'event'     => substr( sanitize_key( $event ), 0, 50 ),
				'direction' => $direction,
				'peer'      => substr( (string) $args['peer'], 0, 191 ),
				'route'     => substr( (string) $args['route'], 0, 191 ),
				'user_id'   => absint( $args['user_id'] ),
				'status'    => $status,
				'detail'    => substr( (string) $args['detail'], 0, 500 ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
		);
	}

	/**
	 * Read log rows.
	 *
	 * @param array $filters Optional: event, status, peer, page, per_page.
	 * @return array{rows:array,total:int,pages:int}
	 */
	public static function query( array $filters = array() ) {
		if ( ! self::is_ready() ) {
			return array(
				'rows'  => array(),
				'total' => 0,
				'pages' => 0,
			);
		}

		global $wpdb;

		$table    = self::table();
		$per_page = isset( $filters['per_page'] ) ? max( 1, min( 200, (int) $filters['per_page'] ) ) : 25;
		$page     = isset( $filters['page'] ) ? max( 1, (int) $filters['page'] ) : 1;
		$offset   = ( $page - 1 ) * $per_page;

		$clauses = array();
		$binds   = array();

		foreach ( array( 'event', 'status', 'peer' ) as $field ) {
			if ( ! empty( $filters[ $field ] ) ) {
				$clauses[] = "{$field} = %s";
				$binds[]   = (string) $filters[ $field ];
			}
		}

		$where = $clauses ? ( 'WHERE ' . implode( ' AND ', $clauses ) ) : '';

		// Count. Runs prepare() only when there is something to bind — calling
		// it with an empty array is the _doing_it_wrong() case described above.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL
		$count_sql = "SELECT COUNT(*) FROM {$table} {$where}";
		$total     = (int) ( $binds
			? $wpdb->get_var( $wpdb->prepare( $count_sql, $binds ) )
			: $wpdb->get_var( $count_sql ) );

		// The page query always binds LIMIT and OFFSET, so prepare() always has
		// at least two placeholders and is always safe to call.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} {$where} ORDER BY id DESC LIMIT %d OFFSET %d",
				array_merge( $binds, array( $per_page, $offset ) )
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL

		return array(
			'rows'  => is_array( $rows ) ? $rows : array(),
			'total' => $total,
			'pages' => (int) ceil( $total / $per_page ),
		);
	}

	/**
	 * Delete rows older than the retention window.
	 *
	 * @return int Rows removed.
	 */
	public static function purge() {
		if ( ! self::is_ready() ) {
			return 0;
		}

		global $wpdb;

		/**
		 * Filter the activity log retention period, in days.
		 *
		 * @param int $days Retention window.
		 */
		$days = (int) apply_filters( 'ls_sso_log_retention_days', self::RETENTION_DAYS );
		$days = max( 1, $days );

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
		$table  = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE logged_at < %s", $cutoff ) );
	}

	/**
	 * Distinct values of a column, for building filter dropdowns.
	 *
	 * @param string $column One of: event, status, peer.
	 * @return array<int,string>
	 */
	public static function distinct( $column ) {
		if ( ! self::is_ready() || ! in_array( $column, array( 'event', 'status', 'peer' ), true ) ) {
			return array();
		}

		global $wpdb;
		$table = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL
		$values = $wpdb->get_col( "SELECT DISTINCT {$column} FROM {$table} ORDER BY {$column} ASC LIMIT 100" );

		return array_values( array_filter( (array) $values ) );
	}

	/**
	 * Drop the table. Used by uninstall.php only.
	 *
	 * @return void
	 */
	public static function drop() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		delete_option( self::SCHEMA_OPTION );
	}
}
