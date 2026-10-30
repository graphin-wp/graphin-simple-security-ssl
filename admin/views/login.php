<?php
/**
 * Vue : connexion (double authentification pour l'instant).
 *
 * @package Graphin\SimpleSecurity
 */

use Graphin\SimpleSecurity\Crypto;
use Graphin\SimpleSecurity\Login\Twofactor;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

$gsss_settings = Settings::all();
$gsss_notice   = isset( $_GET['gsss_notice'] ) ? sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
$gsss_crypto   = Crypto::available();
$gsss_handler  = new Twofactor();
$gsss_users    = get_users(
	array(
		'number'  => 200,
		'orderby' => 'login',
		'fields'  => array( 'ID', 'user_login', 'user_email' ),
	)
);
?>
<?php if ( 'saved' === $gsss_notice ) : ?>
	<div class="notice notice-success inline"><p><?php esc_html_e( 'Réglages enregistrés.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php elseif ( 'reset' === $gsss_notice ) : ?>
	<div class="notice notice-success inline"><p><?php esc_html_e( 'Double authentification réinitialisée. L\'utilisateur a été prévenu par email.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php endif; ?>

<?php if ( ! $gsss_crypto ) : ?>
	<div class="notice notice-error inline"><p><?php esc_html_e( 'Le chiffrement (openssl, AES-256-GCM) n\'est pas disponible sur ce serveur : la double authentification ne peut pas être activée.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php endif; ?>

<form class="gsss-card" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="gsss_save_login">
	<?php wp_nonce_field( 'gsss_save_login' ); ?>

	<h2><?php esc_html_e( 'Double authentification', 'graphin-simple-security-ssl' ); ?></h2>
	<p>
		<label><input type="checkbox" name="login_2fa_enabled" value="1" <?php checked( (int) $gsss_settings['login_2fa_enabled'], 1 ); ?> <?php disabled( ! $gsss_crypto ); ?>> <strong><?php esc_html_e( 'Autoriser la double authentification', 'graphin-simple-security-ssl' ); ?></strong></label><br>
		<span class="description"><?php esc_html_e( 'Chaque utilisateur l\'active lui-même dans son profil : application d\'authentification, code par email en secours, codes de récupération.', 'graphin-simple-security-ssl' ); ?></span>
	</p>
	<p>
		<label><input type="checkbox" name="login_2fa_enforce" value="1" <?php checked( (int) $gsss_settings['login_2fa_enforce'], 1 ); ?>> <?php esc_html_e( 'Imposer la double authentification aux administrateurs', 'graphin-simple-security-ssl' ); ?></label><br>
		<label for="gsss-grace"><?php esc_html_e( 'Délai de grâce, en jours', 'graphin-simple-security-ssl' ); ?></label>
		<input type="number" id="gsss-grace" name="login_2fa_grace" min="0" max="90" value="<?php echo esc_attr( $gsss_settings['login_2fa_grace'] ); ?>" class="small-text"><br>
		<span class="description"><?php esc_html_e( 'Pendant le délai, un rappel s\'affiche dans l\'administration. Ensuite, l\'administrateur est renvoyé vers la configuration de sa double authentification.', 'graphin-simple-security-ssl' ); ?></span>
	</p>
	<p>
		<label><input type="checkbox" name="login_2fa_remember" value="1" <?php checked( (int) $gsss_settings['login_2fa_remember'], 1 ); ?>> <?php esc_html_e( 'Proposer « Se souvenir de cet appareil 30 jours »', 'graphin-simple-security-ssl' ); ?></label>
	</p>
	<p class="description gsss-warning"><?php esc_html_e( 'Un compte protégé ne peut ouvrir une session que depuis la page de connexion WordPress. Les connexions par mot de passe seul depuis un autre formulaire ou XML-RPC sont refusées.', 'graphin-simple-security-ssl' ); ?></p>
	<p><?php submit_button( __( 'Enregistrer', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?></p>
</form>

<section class="gsss-card">
	<h2><?php esc_html_e( 'Utilisateurs', 'graphin-simple-security-ssl' ); ?></h2>
	<table class="widefat striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Identifiant', 'graphin-simple-security-ssl' ); ?></th>
				<th><?php esc_html_e( 'Double authentification', 'graphin-simple-security-ssl' ); ?></th>
				<th></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $gsss_users as $gsss_row ) : ?>
				<?php $gsss_on = Twofactor::user_has_2fa( (int) $gsss_row->ID ); ?>
				<tr>
					<td><?php echo esc_html( $gsss_row->user_login ); ?></td>
					<td><?php echo $gsss_on ? esc_html__( 'Activée', 'graphin-simple-security-ssl' ) : esc_html__( 'Non activée', 'graphin-simple-security-ssl' ); ?></td>
					<td>
						<?php if ( $gsss_on ) : ?>
							<a class="button" data-gsss-confirm="1" href="<?php echo esc_url( $gsss_handler->reset_url( (int) $gsss_row->ID ) ); ?>"><?php esc_html_e( 'Réinitialiser', 'graphin-simple-security-ssl' ); ?></a>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
</section>
