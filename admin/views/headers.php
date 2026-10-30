<?php
/**
 * Vue : en-têtes de sécurité.
 *
 * @package Graphin\SimpleSecurity
 */

use Graphin\SimpleSecurity\CspReports;
use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Modules\Headers;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'is_plugin_active' ) ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

$gsss_settings = Settings::all();
$gsss_options  = Headers::options();
$gsss_notice   = isset( $_GET['gsss_notice'] ) ? sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
$gsss_reports  = CspReports::all();
$gsss_policy   = Headers::policy();
$gsss_enforce  = 'enforce' === $gsss_settings['hdr_csp_mode'];
$gsss_old      = is_plugin_active( 'graphin-hardening/graphin-hardening.php' );
$gsss_apache   = 'apache' === $gsss_settings['server_mode'] && Htaccess::is_writable();
$gsss_messages = array(
	'saved'            => array( 'success', __( 'Réglages enregistrés.', 'graphin-simple-security-ssl' ) ),
	'htaccess_error'   => array( 'warning', __( 'Réglages enregistrés, mais .htaccess n\'a pas pu être mis à jour : les en-têtes passent par PHP. Voir le journal.', 'graphin-simple-security-ssl' ) ),
	'headers_php'      => array( 'warning', __( 'Réglages enregistrés. Les en-têtes écrits dans .htaccess ne sont pas revenus lors du test (module mod_headers absent ?) : ils sont envoyés par PHP.', 'graphin-simple-security-ssl' ) ),
	'csp_allowed'      => array( 'success', __( 'Source ajoutée à la politique.', 'graphin-simple-security-ssl' ) ),
	'csp_unknown'      => array( 'error', __( 'Ce rapport n\'existe plus.', 'graphin-simple-security-ssl' ) ),
	'csp_keyword'      => array( 'error', __( 'Les rapports inline et eval ne s\'autorisent pas d\'un clic : ils demandent de modifier le code du site.', 'graphin-simple-security-ssl' ) ),
	'csp_cleared'      => array( 'success', __( 'Rapports supprimés.', 'graphin-simple-security-ssl' ) ),
	'csp_pending'      => array( 'error', __( 'La CSP ne peut être appliquée tant que des rapports restent dans la liste.', 'graphin-simple-security-ssl' ) ),
	'csp_mode_enforce' => array( 'warning', __( 'CSP appliquée : les ressources non autorisées sont maintenant bloquées.', 'graphin-simple-security-ssl' ) ),
	'csp_mode_report'  => array( 'success', __( 'CSP repassée en rapport seulement.', 'graphin-simple-security-ssl' ) ),
);
?>
<?php if ( isset( $gsss_messages[ $gsss_notice ] ) ) : ?>
	<div class="notice notice-<?php echo esc_attr( $gsss_messages[ $gsss_notice ][0] ); ?> inline"><p><?php echo esc_html( $gsss_messages[ $gsss_notice ][1] ); ?></p></div>
<?php endif; ?>

<?php if ( $gsss_old ) : ?>
	<div class="notice notice-info inline"><p><?php esc_html_e( 'Graph\'in Hardening est actif et envoie déjà plusieurs de ces en-têtes (avec X-XSS-Protection à « 1; mode=block », contraire à la valeur 0 d\'ici). Une fois les cases cochées ici, désactivez-le.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php endif; ?>

<form class="gsss-card" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="gsss_save_headers">
	<?php wp_nonce_field( 'gsss_save_headers' ); ?>

	<p class="description">
		<?php echo ( $gsss_apache && ! Headers::use_php() ) ? esc_html__( 'Les en-têtes sont écrits dans .htaccess (mod_headers). La CSP passe par PHP.', 'graphin-simple-security-ssl' ) : esc_html__( 'Les en-têtes passent par PHP.', 'graphin-simple-security-ssl' ); ?>
	</p>

	<ul class="gsss-options">
		<?php foreach ( $gsss_options as $gsss_key => $gsss_option ) : ?>
			<li class="gsss-option">
				<label class="gsss-switch">
					<input type="checkbox" name="<?php echo esc_attr( $gsss_key ); ?>" value="1" <?php checked( (int) $gsss_settings[ $gsss_key ], 1 ); ?>>
					<span class="gsss-switch__slider" aria-hidden="true"></span>
					<span class="screen-reader-text"><?php echo esc_html( $gsss_option['label'] ); ?></span>
				</label>
				<div class="gsss-option__body">
					<strong><?php echo esc_html( $gsss_option['label'] ); ?></strong>
					<?php if ( $gsss_option['recommended'] ) : ?>
						<span class="gsss-badge gsss-badge--rec"><?php esc_html_e( 'Recommandé', 'graphin-simple-security-ssl' ); ?></span>
					<?php endif; ?>
					<p class="description"><?php echo esc_html( $gsss_option['help'] ); ?></p>
					<?php if ( '' !== $gsss_option['warning'] ) : ?>
						<p class="description gsss-warning"><?php echo esc_html( $gsss_option['warning'] ); ?></p>
					<?php endif; ?>

					<?php if ( 'hdr_referrer' === $gsss_key ) : ?>
						<p>
							<label for="gsss-referrer"><?php esc_html_e( 'Valeur', 'graphin-simple-security-ssl' ); ?></label>
							<select id="gsss-referrer" name="hdr_referrer_value">
								<?php foreach ( Headers::referrer_values() as $gsss_value ) : ?>
									<option value="<?php echo esc_attr( $gsss_value ); ?>" <?php selected( $gsss_settings['hdr_referrer_value'], $gsss_value ); ?>><?php echo esc_html( $gsss_value ); ?></option>
								<?php endforeach; ?>
							</select>
						</p>
					<?php elseif ( 'hdr_permissions' === $gsss_key ) : ?>
						<p>
							<?php foreach ( Headers::features() as $gsss_feature ) : ?>
								<label class="gsss-inline-check"><input type="checkbox" name="hdr_perm_features[]" value="<?php echo esc_attr( $gsss_feature ); ?>" <?php checked( in_array( $gsss_feature, (array) $gsss_settings['hdr_perm_features'], true ) ); ?>> <?php echo esc_html( $gsss_feature ); ?></label>
							<?php endforeach; ?>
						</p>
					<?php endif; ?>
				</div>
			</li>
		<?php endforeach; ?>

		<li class="gsss-option">
			<label class="gsss-switch">
				<input type="checkbox" name="hdr_csp" value="1" <?php checked( (int) $gsss_settings['hdr_csp'], 1 ); ?>>
				<span class="gsss-switch__slider" aria-hidden="true"></span>
				<span class="screen-reader-text"><?php esc_html_e( 'Content-Security-Policy', 'graphin-simple-security-ssl' ); ?></span>
			</label>
			<div class="gsss-option__body">
				<strong><?php esc_html_e( 'Content-Security-Policy', 'graphin-simple-security-ssl' ); ?></strong>
				<span class="gsss-badge gsss-badge--info"><?php echo $gsss_enforce ? esc_html__( 'Appliquée', 'graphin-simple-security-ssl' ) : esc_html__( 'Rapport seulement', 'graphin-simple-security-ssl' ); ?></span>
				<p class="description"><?php esc_html_e( 'Liste les sources autorisées pour les scripts, styles, images et polices. En rapport seulement, rien n\'est bloqué : les violations sont collectées plus bas pour que vous les autorisiez.', 'graphin-simple-security-ssl' ); ?></p>
				<p class="description gsss-warning"><?php esc_html_e( 'La politique de départ garde \'unsafe-inline\' pour rester compatible avec WordPress et Enfold : elle protège peu contre l\'injection de script. C\'est une première étape. Envoyée sur le site public seulement, jamais sur l\'administration.', 'graphin-simple-security-ssl' ); ?></p>
				<p><label><input type="checkbox" name="hdr_csp_upgrade" value="1" <?php checked( (int) $gsss_settings['hdr_csp_upgrade'], 1 ); ?>> <?php esc_html_e( 'Ajouter upgrade-insecure-requests (les ressources http sont chargées en https, sur un site en https)', 'graphin-simple-security-ssl' ); ?></label></p>
			</div>
		</li>
	</ul>

	<p><?php submit_button( __( 'Enregistrer', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?></p>
</form>

<?php if ( (int) $gsss_settings['hdr_csp'] ) : ?>
	<section class="gsss-card">
		<h2><?php esc_html_e( 'Politique CSP actuelle', 'graphin-simple-security-ssl' ); ?></h2>
		<pre class="gsss-code">
		<?php
		foreach ( $gsss_policy as $gsss_directive => $gsss_sources ) {
			echo esc_html( $gsss_directive . ' ' . implode( ' ', $gsss_sources ) ) . "\n";
		}
		?>
		</pre>

		<h3><?php esc_html_e( 'Violations signalées', 'graphin-simple-security-ssl' ); ?></h3>
		<p class="description gsss-warning"><?php esc_html_e( 'Ces domaines sont déclarés par des navigateurs, n\'importe qui peut en proposer un : n\'autorisez que ceux que vous reconnaissez.', 'graphin-simple-security-ssl' ); ?></p>
		<?php if ( empty( $gsss_reports ) ) : ?>
			<p><?php esc_html_e( 'Aucune violation signalée.', 'graphin-simple-security-ssl' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Directive', 'graphin-simple-security-ssl' ); ?></th>
						<th><?php esc_html_e( 'Source bloquée', 'graphin-simple-security-ssl' ); ?></th>
						<th><?php esc_html_e( 'Page', 'graphin-simple-security-ssl' ); ?></th>
						<th><?php esc_html_e( 'Fois', 'graphin-simple-security-ssl' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $gsss_reports as $gsss_id => $gsss_report ) : ?>
						<tr>
							<td><?php echo esc_html( $gsss_report['directive'] ); ?></td>
							<td><code><?php echo esc_html( $gsss_report['source'] ); ?></code></td>
							<td><?php echo esc_html( $gsss_report['doc'] ); ?></td>
							<td><?php echo esc_html( $gsss_report['count'] ); ?></td>
							<td>
								<?php if ( 'keyword' !== $gsss_report['kind'] ) : ?>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
										<input type="hidden" name="action" value="gsss_csp_allow">
										<input type="hidden" name="report" value="<?php echo esc_attr( $gsss_id ); ?>">
										<?php wp_nonce_field( 'gsss_csp_allow' ); ?>
										<button type="submit" class="button"><?php esc_html_e( 'Autoriser', 'graphin-simple-security-ssl' ); ?></button>
									</form>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>

		<p>
			<?php if ( ! empty( $gsss_reports ) ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="gsss-inline-form">
					<input type="hidden" name="action" value="gsss_csp_clear">
					<?php wp_nonce_field( 'gsss_csp_clear' ); ?>
					<button type="submit" class="button"><?php esc_html_e( 'Vider la liste', 'graphin-simple-security-ssl' ); ?></button>
				</form>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="gsss-inline-form" <?php echo ! $gsss_enforce ? 'data-gsss-confirm-msg="' . esc_attr__( 'Appliquer la CSP ? Toute ressource non autorisée sera bloquée sur le site public.', 'graphin-simple-security-ssl' ) . '"' : ''; ?>>
				<input type="hidden" name="action" value="gsss_csp_mode">
				<input type="hidden" name="mode" value="<?php echo $gsss_enforce ? 'report' : 'enforce'; ?>">
				<?php wp_nonce_field( 'gsss_csp_mode' ); ?>
				<button type="submit" class="button <?php echo $gsss_enforce ? '' : 'button-primary'; ?>" <?php disabled( ! $gsss_enforce && ! empty( $gsss_reports ) ); ?>><?php echo $gsss_enforce ? esc_html__( 'Repasser en rapport seulement', 'graphin-simple-security-ssl' ) : esc_html__( 'Passer en mode appliqué', 'graphin-simple-security-ssl' ); ?></button>
			</form>
		</p>
	</section>
<?php endif; ?>

<section class="gsss-card">
	<h2><?php esc_html_e( 'Tester les en-têtes', 'graphin-simple-security-ssl' ); ?></h2>
	<p class="description"><?php esc_html_e( 'Le site demande sa page d\'accueil et affiche les en-têtes réellement reçus.', 'graphin-simple-security-ssl' ); ?></p>
	<p><button type="button" class="button" id="gsss-test-headers"><?php esc_html_e( 'Tester les en-têtes', 'graphin-simple-security-ssl' ); ?></button> <span id="gsss-test-headers-status" role="status" aria-live="polite"></span></p>
	<table class="widefat striped gsss-hidden" id="gsss-test-headers-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'En-tête', 'graphin-simple-security-ssl' ); ?></th>
				<th><?php esc_html_e( 'État', 'graphin-simple-security-ssl' ); ?></th>
				<th><?php esc_html_e( 'Valeur', 'graphin-simple-security-ssl' ); ?></th>
			</tr>
		</thead>
		<tbody></tbody>
	</table>
</section>
