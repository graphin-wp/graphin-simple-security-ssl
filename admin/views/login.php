<?php
/**
 * Vue : connexion (double authentification pour l'instant).
 *
 * @package Graphin\SimpleSecurity
 */

use Graphin\SimpleSecurity\Crypto;
use Graphin\SimpleSecurity\Login\LoginLimiter;
use Graphin\SimpleSecurity\Login\LoginUrl;
use Graphin\SimpleSecurity\Login\Twofactor;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

$gsss_settings = Settings::all();
$gsss_notice   = isset( $_GET['gsss_notice'] ) ? sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
$gsss_crypto   = Crypto::available();
$gsss_handler  = new Twofactor();
$gsss_blocked  = (int) $gsss_settings['login_limit_enabled'] ? LoginLimiter::blocked_list() : array();
$gsss_others   = LoginLimiter::conflicting_plugins();
$gsss_slug     = LoginUrl::slug();
$gsss_slug_err = array(
	'slug_format'    => __( 'Adresse refusée : 3 à 40 caractères, minuscules, chiffres et tirets.', 'graphin-simple-security-ssl' ),
	'slug_reserved'  => __( 'Adresse refusée : ce mot est réservé par WordPress.', 'graphin-simple-security-ssl' ),
	'slug_taken'     => __( 'Adresse refusée : une page, un article ou une catégorie du site l\'utilise déjà.', 'graphin-simple-security-ssl' ),
	'slug_multisite' => __( 'L\'adresse de connexion personnalisée n\'est pas prise en charge en multisite.', 'graphin-simple-security-ssl' ),
);
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
<?php elseif ( isset( $gsss_slug_err[ $gsss_notice ] ) ) : ?>
	<div class="notice notice-error inline"><p><?php echo esc_html( $gsss_slug_err[ $gsss_notice ] ); ?></p></div>
<?php elseif ( 'url_active' === $gsss_notice || 'url_active_nomail' === $gsss_notice ) : ?>
	<div class="notice notice-warning inline"><p>
		<strong><?php esc_html_e( 'Nouvelle adresse de connexion active.', 'graphin-simple-security-ssl' ); ?></strong>
		<?php echo 'url_active' === $gsss_notice ? esc_html__( 'Un email l\'a envoyée à l\'agence et à l\'administrateur du site.', 'graphin-simple-security-ssl' ) : esc_html__( 'L\'email n\'a pas pu partir : notez l\'adresse ci-dessous.', 'graphin-simple-security-ssl' ); ?>
		<?php esc_html_e( 'Avant de fermer cette session, ouvrez l\'adresse dans une fenêtre de navigation privée pour vérifier qu\'elle fonctionne.', 'graphin-simple-security-ssl' ); ?>
	</p></div>
<?php elseif ( 'unblocked' === $gsss_notice ) : ?>
	<div class="notice notice-success inline"><p><?php esc_html_e( 'IP débloquée.', 'graphin-simple-security-ssl' ); ?></p></div>
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

	<h2><?php esc_html_e( 'Adresse de connexion personnalisée', 'graphin-simple-security-ssl' ); ?></h2>
	<p>
		<label><input type="checkbox" name="login_url_enabled" value="1" <?php checked( (int) $gsss_settings['login_url_enabled'], 1 ); ?> <?php disabled( is_multisite() ); ?>> <strong><?php esc_html_e( 'Utiliser une adresse de connexion personnalisée', 'graphin-simple-security-ssl' ); ?></strong></label><br>
		<span class="description"><?php esc_html_e( 'wp-login.php et /wp-admin répondent 404 aux visiteurs non connectés. Un email donne la nouvelle adresse à l\'agence et à l\'administrateur du site.', 'graphin-simple-security-ssl' ); ?></span>
	</p>
	<p>
		<label for="gsss-slug"><?php esc_html_e( 'Adresse', 'graphin-simple-security-ssl' ); ?></label>
		<code><?php echo esc_html( home_url( '/' ) ); ?></code><input type="text" id="gsss-slug" name="login_url_slug" value="<?php echo esc_attr( $gsss_settings['login_url_slug'] ); ?>" class="regular-text" autocomplete="off">
	</p>
	<?php if ( '' !== $gsss_slug ) : ?>
		<p><?php esc_html_e( 'Adresse actuelle :', 'graphin-simple-security-ssl' ); ?> <a href="<?php echo esc_url( LoginUrl::url( $gsss_slug ) ); ?>"><?php echo esc_html( LoginUrl::url( $gsss_slug ) ); ?></a></p>
	<?php endif; ?>
	<p class="description gsss-warning"><?php esc_html_e( 'En cas de blocage : ajoutez define( \'GSSS_SAFE_MODE\', true ); dans wp-config.php, ou renommez le dossier du plugin en FTP. Les liens publics de connexion du site (widget Méta, thème) pointent vers la nouvelle adresse.', 'graphin-simple-security-ssl' ); ?></p>

	<h2><?php esc_html_e( 'Limitation des tentatives de connexion', 'graphin-simple-security-ssl' ); ?></h2>
	<?php if ( ! empty( $gsss_others ) ) : ?>
		<p class="description gsss-warning">
			<?php
			/* translators: %s: noms des extensions */
			echo esc_html( sprintf( __( 'Une extension fait déjà ce travail : %s. Ne gardez qu\'une seule limitation active.', 'graphin-simple-security-ssl' ), implode( ', ', $gsss_others ) ) );
			?>
		</p>
	<?php endif; ?>
	<p>
		<label id="gsss-opt-login_limit_enabled"><input type="checkbox" name="login_limit_enabled" value="1" <?php checked( (int) $gsss_settings['login_limit_enabled'], 1 ); ?>> <strong><?php esc_html_e( 'Bloquer une IP après trop d\'échecs de connexion', 'graphin-simple-security-ssl' ); ?></strong></label><br>
		<span class="description"><?php esc_html_e( 'Le blocage double à chaque récidive, dans la limite de 24 heures. Votre adresse IP actuelle est ajoutée à la liste blanche à l\'activation.', 'graphin-simple-security-ssl' ); ?></span>
	</p>
	<p>
		<label for="gsss-attempts"><?php esc_html_e( 'Nombre d\'essais', 'graphin-simple-security-ssl' ); ?></label>
		<input type="number" id="gsss-attempts" name="login_limit_attempts" min="1" max="50" value="<?php echo esc_attr( $gsss_settings['login_limit_attempts'] ); ?>" class="small-text">
		<label for="gsss-window"><?php esc_html_e( 'dans une fenêtre de (minutes)', 'graphin-simple-security-ssl' ); ?></label>
		<input type="number" id="gsss-window" name="login_limit_window" min="1" max="1440" value="<?php echo esc_attr( $gsss_settings['login_limit_window'] ); ?>" class="small-text">
		<label for="gsss-block"><?php esc_html_e( 'blocage de (minutes)', 'graphin-simple-security-ssl' ); ?></label>
		<input type="number" id="gsss-block" name="login_limit_block" min="1" max="1440" value="<?php echo esc_attr( $gsss_settings['login_limit_block'] ); ?>" class="small-text">
	</p>
	<p>
		<label><input type="checkbox" name="login_proxy" value="1" <?php checked( (int) $gsss_settings['login_proxy'], 1 ); ?>> <?php esc_html_e( 'Site derrière un proxy ou un CDN', 'graphin-simple-security-ssl' ); ?></label><br>
		<span class="description gsss-warning"><?php esc_html_e( 'À cocher seulement si c\'est le cas : l\'IP est alors lue dans X-Forwarded-For (dernière adresse). Sans proxy, cocher cette case ne protège plus rien.', 'graphin-simple-security-ssl' ); ?></span>
	</p>
	<p>
		<label for="gsss-whitelist"><?php esc_html_e( 'Liste blanche (une IP par ligne)', 'graphin-simple-security-ssl' ); ?></label><br>
		<textarea id="gsss-whitelist" name="login_whitelist" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) $gsss_settings['login_whitelist'] ) ); ?></textarea>
	</p>

	<p><?php submit_button( __( 'Enregistrer', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?></p>
</form>

<?php if ( (int) $gsss_settings['login_limit_enabled'] ) : ?>
	<section class="gsss-card">
		<h2><?php esc_html_e( 'IP bloquées', 'graphin-simple-security-ssl' ); ?></h2>
		<?php if ( empty( $gsss_blocked ) ) : ?>
			<p><?php esc_html_e( 'Aucune IP bloquée en ce moment.', 'graphin-simple-security-ssl' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'IP', 'graphin-simple-security-ssl' ); ?></th>
						<th><?php esc_html_e( 'Bloquée jusqu\'à', 'graphin-simple-security-ssl' ); ?></th>
						<th><?php esc_html_e( 'Récidives', 'graphin-simple-security-ssl' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $gsss_blocked as $gsss_ip_row ) : ?>
						<tr>
							<td><?php echo esc_html( $gsss_ip_row['ip'] ); ?></td>
							<td><?php echo esc_html( wp_date( 'd/m/Y H:i', (int) $gsss_ip_row['blocked_until'] ) ); ?></td>
							<td><?php echo esc_html( $gsss_ip_row['strikes'] ); ?></td>
							<td><a class="button" href="<?php echo esc_url( LoginLimiter::unblock_url( $gsss_ip_row['ip'] ) ); ?>"><?php esc_html_e( 'Débloquer', 'graphin-simple-security-ssl' ); ?></a></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</section>
<?php endif; ?>

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
