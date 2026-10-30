<?php
/**
 * Vue : vulnérabilités.
 *
 * @package Graphin\SimpleSecurity
 */

use Graphin\SimpleSecurity\Settings;
use Graphin\SimpleSecurity\VulnScanner;

defined( 'ABSPATH' ) || exit;

$gsss_settings = Settings::all();
$gsss_results  = VulnScanner::results();
$gsss_saved    = isset( $_GET['gsss_notice'] ) && 'saved' === sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
$gsss_levels   = array( 'low', 'medium', 'high', 'critical' );
?>
<?php if ( $gsss_saved ) : ?>
	<div class="notice notice-success inline"><p><?php esc_html_e( 'Réglages enregistrés.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php endif; ?>

<form class="gsss-card" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="gsss_save_vulns">
	<?php wp_nonce_field( 'gsss_save_vulns' ); ?>

	<h2><?php esc_html_e( 'Détection des vulnérabilités', 'graphin-simple-security-ssl' ); ?></h2>
	<p>
		<label><input type="checkbox" name="vuln_enabled" value="1" <?php checked( (int) $gsss_settings['vuln_enabled'], 1 ); ?>> <strong><?php esc_html_e( 'Activer le scan quotidien', 'graphin-simple-security-ssl' ); ?></strong></label><br>
		<span class="description"><?php esc_html_e( 'Interroge wpvulnerability.net pour chaque extension, thème et pour WordPress. Seuls les identifiants des composants sont envoyés (pour WordPress, son numéro de version), jamais l\'adresse du site.', 'graphin-simple-security-ssl' ); ?></span>
	</p>
	<p>
		<label for="gsss-min-severity"><?php esc_html_e( 'Alerter par email à partir de la gravité', 'graphin-simple-security-ssl' ); ?></label>
		<select id="gsss-min-severity" name="vuln_min_severity">
			<?php foreach ( $gsss_levels as $gsss_level ) : ?>
				<option value="<?php echo esc_attr( $gsss_level ); ?>" <?php selected( $gsss_settings['vuln_min_severity'], $gsss_level ); ?>><?php echo esc_html( VulnScanner::label( $gsss_level ) ); ?></option>
			<?php endforeach; ?>
		</select>
	</p>
	<p>
		<label><input type="checkbox" name="vuln_auto_update" value="1" <?php checked( (int) $gsss_settings['vuln_auto_update'], 1 ); ?>> <?php esc_html_e( 'Mettre à jour automatiquement un plugin vulnérable quand une version corrigée est disponible sur wordpress.org', 'graphin-simple-security-ssl' ); ?></label>
	</p>
	<p>
		<label><input type="checkbox" name="vuln_flag_closed" value="1" <?php checked( (int) $gsss_settings['vuln_flag_closed'], 1 ); ?>> <?php esc_html_e( 'Signaler les extensions fermées sur wordpress.org (abandonnées ou retirées)', 'graphin-simple-security-ssl' ); ?></label>
	</p>
	<p><?php submit_button( __( 'Enregistrer', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?></p>
</form>

<section class="gsss-card">
	<h2><?php esc_html_e( 'Résultats', 'graphin-simple-security-ssl' ); ?></h2>
	<p>
		<button type="button" class="button" id="gsss-vuln-scan" <?php disabled( empty( $gsss_settings['vuln_enabled'] ) ); ?>><?php esc_html_e( 'Scanner maintenant', 'graphin-simple-security-ssl' ); ?></button>
		<span id="gsss-vuln-scan-result" role="status" aria-live="polite"></span>
	</p>
	<p class="description">
		<?php
		if ( $gsss_results['time'] ) {
			/* translators: %s: date et heure du dernier scan */
			echo esc_html( sprintf( __( 'Dernier scan : %s', 'graphin-simple-security-ssl' ), wp_date( 'd/m/Y H:i', (int) $gsss_results['time'] ) ) );
			if ( $gsss_results['errors'] ) {
				/* translators: %d: nombre de composants */
				echo ' ' . esc_html( sprintf( _n( '(%d composant n\'a pas pu être analysé)', '(%d composants n\'ont pas pu être analysés)', (int) $gsss_results['errors'], 'graphin-simple-security-ssl' ), (int) $gsss_results['errors'] ) );
			}
		} else {
			esc_html_e( 'Aucun scan effectué pour le moment.', 'graphin-simple-security-ssl' );
		}
		?>
	</p>

	<?php if ( $gsss_results['time'] && empty( $gsss_results['findings'] ) ) : ?>
		<p><?php esc_html_e( 'Aucune vulnérabilité connue sur les versions installées.', 'graphin-simple-security-ssl' ); ?></p>
	<?php elseif ( ! empty( $gsss_results['findings'] ) ) : ?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Composant', 'graphin-simple-security-ssl' ); ?></th>
					<th><?php esc_html_e( 'Version', 'graphin-simple-security-ssl' ); ?></th>
					<th><?php esc_html_e( 'Gravité', 'graphin-simple-security-ssl' ); ?></th>
					<th><?php esc_html_e( 'Description', 'graphin-simple-security-ssl' ); ?></th>
					<th><?php esc_html_e( 'Corrigée en', 'graphin-simple-security-ssl' ); ?></th>
					<th><?php esc_html_e( 'Avis', 'graphin-simple-security-ssl' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $gsss_results['findings'] as $gsss_finding ) : ?>
					<tr>
						<td><?php echo esc_html( $gsss_finding['name'] ); ?></td>
						<td><?php echo esc_html( $gsss_finding['version'] ); ?></td>
						<td><span class="gsss-badge gsss-badge--<?php echo esc_attr( $gsss_finding['severity'] ); ?>"><?php echo esc_html( VulnScanner::label( $gsss_finding['severity'] ) ); ?></span></td>
						<td><?php echo esc_html( $gsss_finding['description'] ); ?></td>
						<td><?php echo '' !== $gsss_finding['fixed'] ? esc_html( $gsss_finding['fixed'] ) : esc_html__( 'Pas de correctif connu', 'graphin-simple-security-ssl' ); ?></td>
						<td>
							<?php if ( '' !== $gsss_finding['link'] ) : ?>
								<a href="<?php echo esc_url( $gsss_finding['link'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Lire', 'graphin-simple-security-ssl' ); ?></a>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</section>

<?php if ( ! empty( $gsss_settings['vuln_flag_closed'] ) && ! empty( $gsss_results['closed'] ) ) : ?>
	<section class="gsss-card">
		<h2><?php esc_html_e( 'Extensions fermées sur wordpress.org', 'graphin-simple-security-ssl' ); ?></h2>
		<ul>
			<?php foreach ( $gsss_results['closed'] as $gsss_closed ) : ?>
				<li>
					<?php echo esc_html( $gsss_closed['name'] ); ?>
					<?php if ( '' !== $gsss_closed['reason'] ) : ?>
						<span class="description">(<?php echo esc_html( $gsss_closed['reason'] ); ?>)</span>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ul>
	</section>
<?php endif; ?>
