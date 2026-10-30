<?php
/**
 * Vue : configuration de la double authentification de l'utilisateur connecté.
 *
 * @package Graphin\SimpleSecurity
 *
 * @var int                                          $gsss_user_id Utilisateur.
 * @var \Graphin\SimpleSecurity\Login\Twofactor      $gsss_page    Gestionnaire.
 * @var string                                       $gsss_notice  Code de message.
 * @var string[]|false                               $gsss_codes   Codes de récupération à afficher une fois.
 * @var string|false                                 $gsss_pending Secret en attente de confirmation.
 * @var \WP_User                                     $gsss_user    Utilisateur.
 */

use Graphin\SimpleSecurity\Crypto;
use Graphin\SimpleSecurity\Login\Twofactor;
use Graphin\SimpleSecurity\Totp;

defined( 'ABSPATH' ) || exit;

$gsss_active   = Twofactor::user_has_2fa( $gsss_user_id );
$gsss_status   = Twofactor::enforcement_for( $gsss_user_id );
$gsss_messages = array(
	'begun'        => array( 'info', __( 'Scannez le code avec votre application, puis saisissez le code qu\'elle affiche.', 'graphin-simple-security-ssl' ) ),
	'cancelled'    => array( 'info', __( 'Activation abandonnée.', 'graphin-simple-security-ssl' ) ),
	'enabled'      => array( 'success', __( 'Double authentification activée. Notez vos codes de récupération.', 'graphin-simple-security-ssl' ) ),
	'regenerated'  => array( 'success', __( 'Nouveaux codes de récupération générés. Les anciens ne fonctionnent plus.', 'graphin-simple-security-ssl' ) ),
	'disabled'     => array( 'success', __( 'Double authentification désactivée.', 'graphin-simple-security-ssl' ) ),
	'bad_code'     => array( 'error', __( 'Code incorrect.', 'graphin-simple-security-ssl' ) ),
	'crypto_error' => array( 'error', __( 'Le secret n\'a pas pu être chiffré : activation annulée.', 'graphin-simple-security-ssl' ) ),
);
?>
<div class="wrap gsss-wrap">
	<h1><?php esc_html_e( 'Double authentification', 'graphin-simple-security-ssl' ); ?></h1>

	<?php if ( isset( $gsss_messages[ $gsss_notice ] ) ) : ?>
		<div class="notice notice-<?php echo esc_attr( $gsss_messages[ $gsss_notice ][0] ); ?> inline"><p><?php echo esc_html( $gsss_messages[ $gsss_notice ][1] ); ?></p></div>
	<?php endif; ?>

	<?php if ( $gsss_status && $gsss_status['expired'] ) : ?>
		<div class="notice notice-error inline"><p><?php esc_html_e( 'La double authentification est obligatoire pour les administrateurs. Configurez-la pour retrouver l\'accès au reste de l\'administration.', 'graphin-simple-security-ssl' ); ?></p></div>
	<?php endif; ?>

	<?php if ( ! Crypto::available() ) : ?>
		<div class="notice notice-error inline"><p><?php esc_html_e( 'Le chiffrement (openssl, AES-256-GCM) n\'est pas disponible sur ce serveur : la double authentification ne peut pas être activée.', 'graphin-simple-security-ssl' ); ?></p></div>
	<?php endif; ?>

	<?php if ( is_array( $gsss_codes ) ) : ?>
		<section class="gsss-card">
			<h2><?php esc_html_e( 'Codes de récupération', 'graphin-simple-security-ssl' ); ?></h2>
			<p><?php esc_html_e( 'Chaque code ne sert qu\'une fois, pour vous connecter si vous perdez votre téléphone. Ils ne seront plus affichés : conservez-les dans un endroit sûr, hors de ce site.', 'graphin-simple-security-ssl' ); ?></p>
			<textarea id="gsss-recovery-codes" class="code" rows="10" cols="16" readonly><?php echo esc_textarea( implode( "\n", $gsss_codes ) ); ?></textarea>
			<p><button type="button" class="button" data-gsss-copy="gsss-recovery-codes"><?php esc_html_e( 'Copier', 'graphin-simple-security-ssl' ); ?></button> <span class="gsss-copy-result" role="status" aria-live="polite"></span></p>
		</section>
	<?php endif; ?>

	<?php if ( $gsss_active ) : ?>
		<section class="gsss-card">
			<h2><?php esc_html_e( 'La double authentification est activée', 'graphin-simple-security-ssl' ); ?></h2>
			<p>
				<?php
				/* translators: %d: nombre de codes */
				echo esc_html( sprintf( _n( 'Il vous reste %d code de récupération.', 'Il vous reste %d codes de récupération.', Twofactor::recovery_left( $gsss_user_id ), 'graphin-simple-security-ssl' ), Twofactor::recovery_left( $gsss_user_id ) ) );
				?>
			</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="gsss_2fa_regen">
				<?php wp_nonce_field( 'gsss_2fa_regen' ); ?>
				<p>
					<label for="gsss-code-regen"><?php esc_html_e( 'Code actuel (application ou récupération)', 'graphin-simple-security-ssl' ); ?></label><br>
					<input type="text" id="gsss-code-regen" name="gsss_code" class="regular-text" autocomplete="one-time-code" required>
					<button type="submit" class="button"><?php esc_html_e( 'Générer de nouveaux codes de récupération', 'graphin-simple-security-ssl' ); ?></button>
				</p>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="gsss_2fa_disable">
				<?php wp_nonce_field( 'gsss_2fa_disable' ); ?>
				<p>
					<label for="gsss-code-disable"><?php esc_html_e( 'Code actuel (application ou récupération)', 'graphin-simple-security-ssl' ); ?></label><br>
					<input type="text" id="gsss-code-disable" name="gsss_code" class="regular-text" autocomplete="one-time-code" required>
					<button type="submit" class="button"><?php esc_html_e( 'Désactiver la double authentification', 'graphin-simple-security-ssl' ); ?></button>
				</p>
			</form>
		</section>

	<?php elseif ( false !== $gsss_pending ) : ?>
		<section class="gsss-card">
			<h2><?php esc_html_e( 'Associer votre application', 'graphin-simple-security-ssl' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Ouvrez votre application d\'authentification (Google Authenticator, Authy, 1Password, Bitwarden...).', 'graphin-simple-security-ssl' ); ?></li>
				<li><?php esc_html_e( 'Scannez ce code, ou saisissez la clé à la main.', 'graphin-simple-security-ssl' ); ?></li>
				<li><?php esc_html_e( 'Saisissez le code à six chiffres affiché pour terminer.', 'graphin-simple-security-ssl' ); ?></li>
			</ol>
			<div id="gsss-qr" data-uri="<?php echo esc_attr( Totp::uri( $gsss_pending, $gsss_user->user_email, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ) ); ?>"></div>
			<p><?php esc_html_e( 'Clé de configuration :', 'graphin-simple-security-ssl' ); ?> <code><?php echo esc_html( trim( chunk_split( $gsss_pending, 4, ' ' ) ) ); ?></code></p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="gsss_2fa_confirm">
				<?php wp_nonce_field( 'gsss_2fa_confirm' ); ?>
				<p>
					<label for="gsss-code-confirm"><?php esc_html_e( 'Code à six chiffres', 'graphin-simple-security-ssl' ); ?></label><br>
					<input type="text" id="gsss-code-confirm" name="gsss_code" class="regular-text" inputmode="numeric" autocomplete="one-time-code" required>
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Activer', 'graphin-simple-security-ssl' ); ?></button>
					<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=gsss_2fa_cancel' ), 'gsss_2fa_cancel' ) ); ?>"><?php esc_html_e( 'Annuler', 'graphin-simple-security-ssl' ); ?></a>
				</p>
			</form>
		</section>

	<?php else : ?>
		<section class="gsss-card">
			<h2><?php esc_html_e( 'Protéger votre compte', 'graphin-simple-security-ssl' ); ?></h2>
			<p><?php esc_html_e( 'À chaque connexion, en plus du mot de passe, un code à six chiffres généré par votre téléphone sera demandé. Un mot de passe volé ne suffit plus.', 'graphin-simple-security-ssl' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="gsss_2fa_begin">
				<?php wp_nonce_field( 'gsss_2fa_begin' ); ?>
				<p><button type="submit" class="button button-primary" <?php disabled( ! Crypto::available() ); ?>><?php esc_html_e( 'Activer la double authentification', 'graphin-simple-security-ssl' ); ?></button></p>
			</form>
		</section>
	<?php endif; ?>
</div>
