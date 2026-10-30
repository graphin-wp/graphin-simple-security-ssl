<?php
/**
 * Vue : réglages généraux (mode serveur, alertes email, journal).
 *
 * @package Graphin\SimpleSecurity
 */

use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

$gsss_settings = Settings::all();
$gsss_rows     = Logger::get_recent();
$gsss_notice   = isset( $_GET['gsss_notice'] ) ? sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
$gsss_messages = array(
	'saved'          => array( 'success', __( 'Réglages enregistrés.', 'graphin-simple-security-ssl' ) ),
	'invalid_email'  => array( 'error', __( 'Adresse email invalide : rien n\'a été enregistré.', 'graphin-simple-security-ssl' ) ),
	'htaccess_error' => array( 'warning', __( 'Réglages enregistrés, mais .htaccess n\'a pas pu être mis à jour. Voir le journal.', 'graphin-simple-security-ssl' ) ),
);
?>
<?php if ( isset( $gsss_messages[ $gsss_notice ] ) ) : ?>
	<div class="notice notice-<?php echo esc_attr( $gsss_messages[ $gsss_notice ][0] ); ?> inline"><p><?php echo esc_html( $gsss_messages[ $gsss_notice ][1] ); ?></p></div>
<?php endif; ?>

<?php if ( 'apache' === $gsss_settings['server_mode'] && ! Htaccess::is_writable() ) : ?>
	<div class="notice notice-warning inline"><p><?php esc_html_e( 'Le fichier .htaccess n\'est pas inscriptible : les règles qui le demandent passeront par PHP quand c\'est possible.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php endif; ?>

<form class="gsss-card" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="gsss_save_settings">
	<?php wp_nonce_field( 'gsss_save_settings' ); ?>

	<h2><?php esc_html_e( 'Mode serveur', 'graphin-simple-security-ssl' ); ?></h2>
	<p>
		<label><input type="radio" name="server_mode" value="apache" <?php checked( $gsss_settings['server_mode'], 'apache' ); ?>> <?php esc_html_e( 'Apache (.htaccess), par défaut', 'graphin-simple-security-ssl' ); ?></label><br>
		<label><input type="radio" name="server_mode" value="other" <?php checked( $gsss_settings['server_mode'], 'other' ); ?>> <?php esc_html_e( 'Autre serveur (Nginx, etc.) : aucune écriture dans .htaccess', 'graphin-simple-security-ssl' ); ?></label>
	</p>

	<h2><?php esc_html_e( 'Alertes par email', 'graphin-simple-security-ssl' ); ?></h2>
	<p>
		<label for="gsss-agency-email"><?php esc_html_e( 'Adresse de l\'agence', 'graphin-simple-security-ssl' ); ?></label><br>
		<input type="email" id="gsss-agency-email" name="agency_email" class="regular-text" value="<?php echo esc_attr( $gsss_settings['agency_email'] ); ?>" required>
	</p>
	<p>
		<label><input type="checkbox" name="alert_client" value="1" <?php checked( (int) $gsss_settings['alert_client'], 1 ); ?>> <?php esc_html_e( 'Envoyer aussi les alertes au client', 'graphin-simple-security-ssl' ); ?></label>
	</p>
	<p>
		<label for="gsss-client-email"><?php esc_html_e( 'Adresse du client', 'graphin-simple-security-ssl' ); ?></label><br>
		<input type="email" id="gsss-client-email" name="client_email" class="regular-text" value="<?php echo esc_attr( '' !== $gsss_settings['client_email'] ? $gsss_settings['client_email'] : get_option( 'admin_email' ) ); ?>">
	</p>

	<p>
		<?php submit_button( __( 'Enregistrer', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?>
		<button type="button" class="button" id="gsss-test-mail"><?php esc_html_e( 'Envoyer un email de test', 'graphin-simple-security-ssl' ); ?></button>
		<span id="gsss-test-mail-result" role="status" aria-live="polite"></span>
	</p>
	<p class="description"><?php esc_html_e( 'Le test utilise les adresses enregistrées : enregistrez d\'abord vos changements.', 'graphin-simple-security-ssl' ); ?></p>
</form>

<section class="gsss-card">
	<h2><?php esc_html_e( 'Journal', 'graphin-simple-security-ssl' ); ?></h2>
	<?php if ( empty( $gsss_rows ) ) : ?>
		<p><?php esc_html_e( 'Aucun événement pour le moment.', 'graphin-simple-security-ssl' ); ?></p>
	<?php else : ?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Date', 'graphin-simple-security-ssl' ); ?></th>
					<th><?php esc_html_e( 'Niveau', 'graphin-simple-security-ssl' ); ?></th>
					<th><?php esc_html_e( 'Événement', 'graphin-simple-security-ssl' ); ?></th>
					<th><?php esc_html_e( 'Détail', 'graphin-simple-security-ssl' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $gsss_rows as $gsss_row ) : ?>
					<tr>
						<td><?php echo esc_html( get_date_from_gmt( $gsss_row['created_at'], 'd/m/Y H:i' ) ); ?></td>
						<td><?php echo esc_html( $gsss_row['level'] ); ?></td>
						<td><?php echo esc_html( $gsss_row['event'] ); ?></td>
						<td><?php echo esc_html( $gsss_row['message'] ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</section>
