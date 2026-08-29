<?php
/**
 * Status screen, settings form, activity log, and health checks.
 *
 * ---------------------------------------------------------------------------
 * ON EDITING THE SECRET HERE
 * ---------------------------------------------------------------------------
 * wp-config.php remains the better home for the shared secret: outside the
 * database, outside every backup and export, changeable only with file access.
 * When the constant is defined, this screen shows it read-only and will not
 * write a value the constant would immediately override.
 *
 * But plenty of managed hosts allow plugin installation and no file access at
 * all -- WordPress.com grants SFTP only on Business and Commerce, while plugins
 * install on every paid plan. Refusing the secret anywhere else does not make
 * those sites safer; it makes the plugin unusable on them. So the field exists,
 * with three mitigations: the option is stored with autoload off, the value is
 * never rendered back to the screen, and the screen says plainly when a value
 * is living in the database rather than in a file.
 *
 * What is shown instead is a short SHA-256 fingerprint -- enough to confirm
 * that three sites hold the same secret without displaying it anywhere.
 *
 * @package Leadstart_SSO
 */

defined( 'ABSPATH' ) || exit;

/**
 * Admin status page.
 */
class LS_SSO_Admin {

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_page' ) );
		add_action( 'admin_notices', array( __CLASS__, 'config_notice' ) );
	}

	/**
	 * Add the Tools submenu page.
	 *
	 * @return void
	 */
	public static function add_page() {
		add_management_page(
			__( 'Leadstart SSO', 'leadstart-sso' ),
			__( 'Leadstart SSO', 'leadstart-sso' ),
			'manage_options',
			'leadstart-sso',
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * Warn loudly when the plugin is installed but not configured.
	 *
	 * @return void
	 */
	public static function config_notice() {
		if ( ! current_user_can( 'manage_options' ) || LS_SSO_Config::is_configured() ) {
			return;
		}

		echo '<div class="notice notice-error"><p><strong>';
		esc_html_e( 'Leadstart SSO is inactive.', 'leadstart-sso' );
		echo '</strong> ';
		esc_html_e( 'Set the shared secret and peer sites under Tools > Leadstart SSO, or define LS_SSO_SECRET and LS_SSO_PEERS in wp-config.php. Federation, silent login, and global logout are all switched off until then.', 'leadstart-sso' );
		echo '</p></div>';
	}

	/**
	 * Render the status page.
	 *
	 * @return void
	 */
	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'leadstart-sso' ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab switch.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'status';
		$tab = in_array( $tab, array( 'status', 'settings', 'activity' ), true ) ? $tab : 'status';
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Leadstart SSO', 'leadstart-sso' ); ?></h1>
			<nav class="nav-tab-wrapper">
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=leadstart-sso&tab=status' ) ); ?>"
				   class="nav-tab <?php echo 'status' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Status', 'leadstart-sso' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=leadstart-sso&tab=settings' ) ); ?>"
				   class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Settings', 'leadstart-sso' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=leadstart-sso&tab=activity' ) ); ?>"
				   class="nav-tab <?php echo 'activity' === $tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Activity', 'leadstart-sso' ); ?>
				</a>
			</nav>
			<?php
			if ( 'activity' === $tab ) {
				self::render_activity();
			} elseif ( 'settings' === $tab ) {
				self::render_settings();
			} else {
				self::render_status();
			}
			?>
		</div>
		<?php
	}

	/**
	 * Status tab.
	 *
	 * @return void
	 */
	protected static function render_status() {
		$peers = LS_SSO_Config::peers();
		$ran   = false;
		$results = array();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_POST['ls_sso_test'] ) && check_admin_referer( 'ls_sso_test' ) ) {
			$ran     = true;
			$results = self::run_connectivity_test( $peers );
		}
		?>
			<h2><?php esc_html_e( 'Configuration', 'leadstart-sso' ); ?></h2>
			<table class="widefat striped" style="max-width:60em">
				<tbody>
					<?php
					self::row(
						__( 'Shared secret', 'leadstart-sso' ),
						LS_SSO_Config::secret()
							? sprintf(
								/* translators: 1: where the value came from, 2: short fingerprint. */
								__( 'Set via %1$s — fingerprint %2$s (must match on every site)', 'leadstart-sso' ),
								'constant' === LS_SSO_Config::source_of( 'LS_SSO_SECRET' ) ? 'wp-config.php' : __( 'the Settings tab', 'leadstart-sso' ),
								LS_SSO_Config::secret_fingerprint()
							)
							: __( 'Missing — set it on the Settings tab or in wp-config.php', 'leadstart-sso' ),
						(bool) LS_SSO_Config::secret()
					);
					self::row(
						__( 'This site', 'leadstart-sso' ),
						LS_SSO_Config::self_origin(),
						true
					);
					self::row(
						__( 'Peers', 'leadstart-sso' ),
						$peers ? implode( ', ', $peers ) : __( 'None configured', 'leadstart-sso' ),
						! empty( $peers )
					);
					self::row(
						__( 'Role on the network', 'leadstart-sso' ),
						LS_SSO_Config::is_store()
							? __( 'Store — serves order history', 'leadstart-sso' )
							: __( 'Satellite — reads order history', 'leadstart-sso' ),
						true
					);
					self::row(
						__( 'OpenID Connect Generic', 'leadstart-sso' ),
						class_exists( 'OpenID_Connect_Generic' )
							? __( 'Active', 'leadstart-sso' )
							: __( 'Not active — silent login and claim mapping are off', 'leadstart-sso' ),
						class_exists( 'OpenID_Connect_Generic' )
					);
					self::row(
						__( 'Silent SSO', 'leadstart-sso' ),
						LS_SSO_Config::silent_enabled()
							/* translators: %s: transport mode. */
							? sprintf( __( 'On (%s transport)', 'leadstart-sso' ), LS_SSO_Config::silent_mode() )
							: __( 'Off', 'leadstart-sso' ),
						LS_SSO_Config::silent_enabled()
					);
					self::row(
						__( 'Silent login refused for', 'leadstart-sso' ),
						LS_SSO_Config::blocked_silent_roles()
							? implode( ', ', LS_SSO_Config::blocked_silent_roles() )
							: __( 'No role — every role may be signed in silently', 'leadstart-sso' ),
						! empty( LS_SSO_Config::blocked_silent_roles() )
					);
					self::row(
						__( 'Synced meta keys', 'leadstart-sso' ),
						LS_SSO_Config::meta_keys()
							? implode( ', ', LS_SSO_Config::meta_keys() )
							: __( 'None — nothing is pushed between sites', 'leadstart-sso' ),
						true
					);
					?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'Connectivity', 'leadstart-sso' ); ?></h2>
			<p class="description">
				<?php esc_html_e( 'Sends a signed request to each peer. A 403 almost always means the shared secret differs between the two sites.', 'leadstart-sso' ); ?>
			</p>

			<form method="post">
				<?php wp_nonce_field( 'ls_sso_test' ); ?>
				<?php submit_button( __( 'Test peers', 'leadstart-sso' ), 'secondary', 'ls_sso_test', false ); ?>
			</form>

			<?php if ( $ran ) : ?>
				<table class="widefat striped" style="max-width:60em;margin-top:1em">
					<tbody>
					<?php foreach ( $results as $origin => $result ) : ?>
						<?php self::row( $origin, $result['message'], $result['ok'] ); ?>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Shared secret', 'leadstart-sso' ); ?></h2>
			<p class="description" style="max-width:60em">
				<?php esc_html_e( 'The secret lives in wp-config.php, not the database, so it stays out of backups and exports and cannot drift between sites. Generate one below and paste the line into every participating site.', 'leadstart-sso' ); ?>
			</p>
			<p>
				<button type="button" class="button" id="ls-sso-generate">
					<?php esc_html_e( 'Generate a secret', 'leadstart-sso' ); ?>
				</button>
			</p>
			<p id="ls-sso-generated" style="display:none">
				<label for="ls-sso-secret-line" class="screen-reader-text">
					<?php esc_html_e( 'Generated configuration line', 'leadstart-sso' ); ?>
				</label>
				<textarea id="ls-sso-secret-line" rows="2" readonly
					style="width:100%;max-width:60em;font-family:monospace"></textarea>
				<span class="description">
					<?php esc_html_e( 'Generated in your browser. It is never sent to this server, and is not stored anywhere until you paste it into wp-config.php.', 'leadstart-sso' ); ?>
				</span>
			</p>
			<script>
			( function () {
				var button = document.getElementById( 'ls-sso-generate' );
				if ( ! button ) { return; }
				button.addEventListener( 'click', function () {
					var bytes = new Uint8Array( 32 );
					window.crypto.getRandomValues( bytes );
					var hex = Array.prototype.map.call( bytes, function ( b ) {
						return b.toString( 16 ).padStart( 2, '0' );
					} ).join( '' );
					var field = document.getElementById( 'ls-sso-secret-line' );
					field.value = "define( 'LS_SSO_SECRET', '" + hex + "' );";
					document.getElementById( 'ls-sso-generated' ).style.display = '';
					field.focus();
					field.select();
				} );
			} )();
			</script>
		<?php
	}

	/**
	 * Settings tab.
	 *
	 * Exists because not every host lets you edit wp-config.php. Any value set
	 * by a constant is shown read-only here, because saving a value the
	 * constant would immediately override is worse than not offering the field.
	 *
	 * @return void
	 */
	protected static function render_settings() {
		$fields = array(
			'LS_SSO_SECRET'             => array(
				'label'  => __( 'Shared secret', 'leadstart-sso' ),
				'type'   => 'secret',
				'help'   => __( 'A 64-character hex string, identical on every participating site. Once saved it is never shown again — only its fingerprint, so you can confirm all sites match.', 'leadstart-sso' ),
			),
			'LS_SSO_PEERS'              => array(
				'label'  => __( 'Peer sites', 'leadstart-sso' ),
				'type'   => 'text',
				'help'   => __( 'Comma-separated origins of the OTHER sites, e.g. https://a.example.com,https://b.example.com', 'leadstart-sso' ),
			),
			'LS_SSO_STORE'              => array(
				'label'  => __( 'Store site', 'leadstart-sso' ),
				'type'   => 'text',
				'help'   => __( 'Origin of the site running WooCommerce. The same value on every site.', 'leadstart-sso' ),
			),
			'LS_SSO_ROLE_CLAIM'         => array(
				'label'  => __( 'Role claim', 'leadstart-sso' ),
				'type'   => 'text',
				'help'   => __( 'Optional. Namespaced claim carrying roles, e.g. https://example.com/roles — must be a domain you control. Auth0 silently discards claims namespaced under auth0.com, webtask.io or webtask.run.', 'leadstart-sso' ),
			),
			'LS_SSO_META_KEYS'          => array(
				'label'  => __( 'Synced meta keys', 'leadstart-sso' ),
				'type'   => 'text',
				'help'   => __( 'Optional. Comma-separated user meta keys allowed to travel between sites. Leave empty to sync nothing.', 'leadstart-sso' ),
			),
			'LS_SSO_BLOCK_SILENT_ROLES' => array(
				'label'  => __( 'Never sign in silently', 'leadstart-sso' ),
				'type'   => 'text',
				'help'   => __( 'Comma-separated roles refused a silent session. Interactive login still works for them. Default: administrator.', 'leadstart-sso' ),
			),
		);

		$submitted = false;
		$changed   = array();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['ls_sso_save'] ) && check_admin_referer( 'ls_sso_save_settings' ) ) {
			$submitted = true;

			foreach ( $fields as $constant => $field ) {
				if ( defined( $constant ) || ! isset( $_POST[ $constant ] ) ) {
					continue;
				}

				$value = sanitize_text_field( wp_unslash( $_POST[ $constant ] ) );

				if ( 'secret' === $field['type'] ) {
					// Blank means "leave it alone", not "clear it" — otherwise
					// simply saving the form wipes the secret every time.
					if ( '' === $value ) {
						continue;
					}
					if ( ! preg_match( '/\A[A-Za-z0-9+\/=_-]{32,255}\z/', $value ) ) {
						add_settings_error(
							'ls_sso',
							'bad_secret',
							__( 'The shared secret was NOT saved: it must be 32 to 255 characters, with no spaces or punctuation beyond + / = _ and -.', 'leadstart-sso' )
						);
						continue;
					}
				}

				if ( LS_SSO_Config::save( $constant, $value ) ) {
					$changed[] = $field['label'];
				}
			}
		}

		settings_errors( 'ls_sso' );

		// Report exactly what was written. A blanket "Settings saved." after a
		// no-op is how a write-only field convinces someone it stored a value
		// it never received.
		if ( $submitted ) {
			if ( ! empty( $changed ) ) {
				echo '<div class="notice notice-success is-dismissible"><p>' .
					esc_html(
						sprintf(
							/* translators: %s: comma-separated list of setting names. */
							__( 'Updated: %s', 'leadstart-sso' ),
							implode( ', ', $changed )
						)
					) . '</p></div>';
			} elseif ( ! get_settings_errors( 'ls_sso' ) ) {
				echo '<div class="notice notice-warning is-dismissible"><p>' .
					esc_html__( 'Nothing changed. The shared secret field is intentionally blank on every page load — fill it in only when you want to replace the stored value.', 'leadstart-sso' ) .
					'</p></div>';
			}
		}
		?>
		<p class="description" style="max-width:60em;margin:1em 0">
			<?php esc_html_e( 'Values defined in wp-config.php always win and are shown here read-only. Use these fields when you cannot edit that file — some managed hosts allow plugin installation but no file access.', 'leadstart-sso' ); ?>
		</p>

		<form method="post">
			<?php wp_nonce_field( 'ls_sso_save_settings' ); ?>
			<table class="form-table" role="presentation">
				<tbody>
				<?php foreach ( $fields as $constant => $field ) : ?>
					<?php
					$locked = defined( $constant );
					$source = LS_SSO_Config::source_of( $constant );
					?>
					<tr>
						<th scope="row">
							<label for="<?php echo esc_attr( $constant ); ?>">
								<?php echo esc_html( $field['label'] ); ?>
							</label>
						</th>
						<td>
							<?php if ( $locked ) : ?>
								<p>
									<strong><?php esc_html_e( 'Set in wp-config.php', 'leadstart-sso' ); ?></strong>
									<?php if ( 'secret' !== $field['type'] ) : ?>
										— <code><?php echo esc_html( constant( $constant ) ); ?></code>
									<?php endif; ?>
								</p>
							<?php elseif ( 'secret' === $field['type'] ) : ?>
								<input type="password" class="regular-text" autocomplete="new-password"
									id="<?php echo esc_attr( $constant ); ?>"
									name="<?php echo esc_attr( $constant ); ?>" value=""
									placeholder="<?php echo esc_attr__( 'Leave blank to keep the current secret', 'leadstart-sso' ); ?>" />
							<?php else : ?>
								<input type="text" class="regular-text"
									id="<?php echo esc_attr( $constant ); ?>"
									name="<?php echo esc_attr( $constant ); ?>"
									value="<?php echo esc_attr( self::current_value( $constant ) ); ?>" />
							<?php endif; ?>

							<?php if ( 'secret' === $field['type'] ) : ?>
								<?php if ( LS_SSO_Config::secret() ) : ?>
									<p style="margin-top:.6em">
										<span style="color:#1f6f4a" aria-hidden="true">&#9679;</span>
										<strong><?php esc_html_e( 'A secret is stored.', 'leadstart-sso' ); ?></strong>
										<?php esc_html_e( 'Fingerprint:', 'leadstart-sso' ); ?>
										<code><?php echo esc_html( LS_SSO_Config::secret_fingerprint() ); ?></code>
										<br>
										<?php esc_html_e( 'This exact fingerprint must appear on every participating site. The field above stays blank by design — the secret is never displayed again.', 'leadstart-sso' ); ?>
									</p>
								<?php else : ?>
									<p style="margin-top:.6em">
										<span style="color:#a32020" aria-hidden="true">&#9679;</span>
										<strong><?php esc_html_e( 'No secret is stored yet.', 'leadstart-sso' ); ?></strong>
										<?php esc_html_e( 'Nothing works until one is set here or in wp-config.php.', 'leadstart-sso' ); ?>
									</p>
								<?php endif; ?>
							<?php endif; ?>

							<p class="description">
								<?php echo esc_html( $field['help'] ); ?>
								<?php if ( 'option' === $source ) : ?>
									<br><em><?php esc_html_e( 'Currently stored in the database. Moving it to wp-config.php keeps it out of backups and exports.', 'leadstart-sso' ); ?></em>
								<?php endif; ?>
							</p>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php submit_button( __( 'Save settings', 'leadstart-sso' ), 'primary', 'ls_sso_save' ); ?>
		</form>
		<?php
	}

	/**
	 * Current stored value of a setting, for pre-filling a form field.
	 *
	 * Never used for the secret.
	 *
	 * @param string $constant Constant name.
	 * @return string
	 */
	protected static function current_value( $constant ) {
		switch ( $constant ) {
			case 'LS_SSO_PEERS':
				return implode( ',', LS_SSO_Config::peers() );
			case 'LS_SSO_STORE':
				return LS_SSO_Config::store_origin();
			case 'LS_SSO_ROLE_CLAIM':
				return LS_SSO_Config::role_claim();
			case 'LS_SSO_META_KEYS':
				return implode( ',', LS_SSO_Config::meta_keys() );
			case 'LS_SSO_BLOCK_SILENT_ROLES':
				return implode( ',', LS_SSO_Config::blocked_silent_roles() );
		}
		return '';
	}

	/**
	 * Activity tab.
	 *
	 * @return void
	 */
	protected static function render_activity() {
		if ( ! LS_SSO_Logger::is_ready() ) {
			echo '<p>' . esc_html__( 'The activity table has not been created yet. Reload this page once the plugin has finished initialising.', 'leadstart-sso' ) . '</p>';
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only filters.
		$filters = array(
			'event'  => isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '',
			'status' => isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : '',
			'page'   => isset( $_GET['paged'] ) ? absint( wp_unslash( $_GET['paged'] ) ) : 1,
		);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$result = LS_SSO_Logger::query( $filters );
		$events = LS_SSO_Logger::distinct( 'event' );
		?>
		<form method="get" style="margin:1em 0">
			<input type="hidden" name="page" value="leadstart-sso" />
			<input type="hidden" name="tab" value="activity" />
			<label for="ls-sso-filter-event" class="screen-reader-text">
				<?php esc_html_e( 'Filter by event', 'leadstart-sso' ); ?>
			</label>
			<select name="event" id="ls-sso-filter-event">
				<option value=""><?php esc_html_e( 'All events', 'leadstart-sso' ); ?></option>
				<?php foreach ( $events as $event ) : ?>
					<option value="<?php echo esc_attr( $event ); ?>" <?php selected( $filters['event'], $event ); ?>>
						<?php echo esc_html( $event ); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<label for="ls-sso-filter-status" class="screen-reader-text">
				<?php esc_html_e( 'Filter by status', 'leadstart-sso' ); ?>
			</label>
			<select name="status" id="ls-sso-filter-status">
				<option value=""><?php esc_html_e( 'Any status', 'leadstart-sso' ); ?></option>
				<option value="success" <?php selected( $filters['status'], 'success' ); ?>>
					<?php esc_html_e( 'Success', 'leadstart-sso' ); ?>
				</option>
				<option value="failure" <?php selected( $filters['status'], 'failure' ); ?>>
					<?php esc_html_e( 'Failure', 'leadstart-sso' ); ?>
				</option>
			</select>
			<?php submit_button( __( 'Filter', 'leadstart-sso' ), 'secondary', '', false ); ?>
		</form>

		<table class="widefat striped">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Time (UTC)', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Event', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Direction', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Peer', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'User', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Status', 'leadstart-sso' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Detail', 'leadstart-sso' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php if ( empty( $result['rows'] ) ) : ?>
				<tr><td colspan="7"><?php esc_html_e( 'No activity recorded.', 'leadstart-sso' ); ?></td></tr>
			<?php else : ?>
				<?php foreach ( $result['rows'] as $row ) : ?>
					<tr>
						<td><?php echo esc_html( $row['logged_at'] ); ?></td>
						<td><code><?php echo esc_html( $row['event'] ); ?></code></td>
						<td><?php echo esc_html( $row['direction'] ); ?></td>
						<td><?php echo esc_html( $row['peer'] ); ?></td>
						<td>
							<?php echo (int) $row['user_id'] ? esc_html( (string) (int) $row['user_id'] ) : '&mdash;'; ?>
						</td>
						<td>
							<span style="color:<?php echo 'failure' === $row['status'] ? '#a32020' : '#1f6f4a'; ?>">
								<?php echo esc_html( $row['status'] ); ?>
							</span>
						</td>
						<td><?php echo esc_html( (string) $row['detail'] ); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>

		<?php if ( $result['pages'] > 1 ) : ?>
			<div class="tablenav"><div class="tablenav-pages">
				<?php
				echo wp_kses_post(
					paginate_links(
						array(
							'base'      => add_query_arg( 'paged', '%#%' ),
							'format'    => '',
							'current'   => max( 1, (int) $filters['page'] ),
							'total'     => (int) $result['pages'],
							'prev_text' => '&laquo;',
							'next_text' => '&raquo;',
						)
					)
				);
				?>
			</div></div>
		<?php endif; ?>

		<p class="description">
			<?php
			printf(
				/* translators: %d: number of days entries are retained. */
				esc_html__( 'Entries older than %d days are deleted automatically.', 'leadstart-sso' ),
				(int) apply_filters( 'ls_sso_log_retention_days', LS_SSO_Logger::RETENTION_DAYS )
			);
			?>
		</p>
		<?php
	}

	/**
	 * Probe each peer with a harmless signed request.
	 *
	 * @param array $peers Peer origins.
	 * @return array<string,array{ok:bool,message:string}>
	 */
	protected static function run_connectivity_test( array $peers ) {
		$out = array();

		foreach ( $peers as $origin ) {
			// A subject that matches nobody: the peer answers 200 with
			// reason "unknown_subject", proving the signature verified without
			// changing any data.
			$result = LS_SSO_Http::post(
				$origin,
				'/leadstart-sso/v1/usermeta',
				array(
					'subject' => 'ls-sso-connectivity-probe',
					'meta'    => new stdClass(),
				),
				10
			);

			if ( is_wp_error( $result ) ) {
				$out[ $origin ] = array(
					'ok'      => false,
					'message' => self::explain_failure( $result ),
				);
				continue;
			}

			$out[ $origin ] = array(
				'ok'      => true,
				'message' => __( 'Signed request accepted — this peer shares your secret.', 'leadstart-sso' ),
			);
		}

		return $out;
	}

	/**
	 * Turn a peer failure into something that points at the actual cause.
	 *
	 * The status code is the whole diagnosis here, and the three common ones
	 * mean completely different things:
	 *
	 *   404 — no route. The plugin is not installed or not active on the peer.
	 *         Note that the secret was never checked, so a 404 says nothing
	 *         about whether the secrets match.
	 *   503 — the plugin is there but has no secret or peers configured yet.
	 *   403 — the request was signed and rejected. THIS is the mismatched
	 *         secret case, and the only one where comparing fingerprints helps.
	 *
	 * @param WP_Error $error The failure.
	 * @return string
	 */
	protected static function explain_failure( WP_Error $error ) {
		$code = $error->get_error_code();

		if ( 'ls_sso_http_404' === $code ) {
			return __( 'Not found (404). The plugin is not installed or not activated on that site — its REST route does not exist. Your secret was never checked, so this says nothing about whether the secrets match.', 'leadstart-sso' );
		}

		if ( 'ls_sso_http_503' === $code ) {
			return __( 'Unconfigured (503). The plugin is installed on that site but has no shared secret or peer list yet. Configure it there, then test again.', 'leadstart-sso' );
		}

		if ( 'ls_sso_http_403' === $code ) {
			return __( 'Rejected (403). That site received the signed request and refused it — the shared secret differs. Compare the fingerprint on both sites; they must be identical.', 'leadstart-sso' );
		}

		if ( 'ls_sso_http_401' === $code ) {
			return __( 'Unauthorized (401). Something in front of that site is blocking the request, such as HTTP basic auth, a firewall, or a "coming soon" plugin.', 'leadstart-sso' );
		}

		if ( 'ls_sso_bad_body' === $code ) {
			return __( 'That site answered, but not with JSON. A caching layer or a maintenance page is probably intercepting the REST route.', 'leadstart-sso' );
		}

		return $error->get_error_message();
	}

	/**
	 * Render one status row.
	 *
	 * @param string $label Row label.
	 * @param string $value Row value.
	 * @param bool   $ok    Whether this is a healthy state.
	 * @return void
	 */
	protected static function row( $label, $value, $ok ) {
		?>
		<tr>
			<th scope="row" style="width:14em"><?php echo esc_html( $label ); ?></th>
			<td>
				<span aria-hidden="true" style="color:<?php echo $ok ? '#1f6f4a' : '#a32020'; ?>">&#9679;</span>
				<span class="screen-reader-text">
					<?php echo esc_html( $ok ? __( 'OK:', 'leadstart-sso' ) : __( 'Problem:', 'leadstart-sso' ) ); ?>
				</span>
				<?php echo esc_html( $value ); ?>
			</td>
		</tr>
		<?php
	}
}
