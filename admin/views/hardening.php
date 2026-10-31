<?php
/**
 * Vue : durcissement.
 *
 * @package Graphin\SimpleSecurity
 */

use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Modules\Hardening;
use Graphin\SimpleSecurity\Plugin;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

$gsss_settings = Settings::all();
$gsss_options  = Hardening::options();
$gsss_notice   = isset( $_GET['gsss_notice'] ) ? sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
$gsss_apache   = 'apache' === $gsss_settings['server_mode'] && Htaccess::is_writable();
$gsss_flagged  = Hardening::flagged_users();
$gsss_role     = Hardening::risky_registration_role();
$gsss_modules  = Plugin::instance()->modules();
$gsss_snippet  = isset( $gsss_modules['hardening'] ) && ! $gsss_apache ? $gsss_modules['hardening']->nginx_rules() : '';
$gsss_overlap  = array( 'hard_xmlrpc', 'hard_pingbacks', 'hard_opcache_notice' );
$gsss_old      = \Graphin\SimpleSecurity\Dashboard::hardening_active();
?>
<?php if ( 'saved' === $gsss_notice ) : ?>
	<div class="notice notice-success inline"><p><?php esc_html_e( 'Réglages enregistrés.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php elseif ( 'htaccess_error' === $gsss_notice ) : ?>
	<div class="notice notice-warning inline"><p><?php esc_html_e( 'Réglages enregistrés, mais .htaccess n\'a pas pu être mis à jour. Voir le journal dans les réglages généraux.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php endif; ?>

<?php if ( $gsss_old ) : ?>
	<div class="notice notice-info inline"><p><?php esc_html_e( 'Graph\'in Hardening est actif. Les cases XML-RPC, Pingbacks et Test OPcache font la même chose : une fois cochées ici, vous pouvez désactiver Graph\'in Hardening.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php endif; ?>

<?php if ( ! empty( $gsss_flagged ) ) : ?>
	<div class="notice notice-warning inline"><p>
		<?php
		/* translators: %s: identifiants des comptes */
		echo esc_html( sprintf( __( 'Comptes existants avec un identifiant interdit : %s. Créez un compte administrateur avec un autre identifiant, puis supprimez celui-ci.', 'graphin-simple-security-ssl' ), implode( ', ', $gsss_flagged ) ) );
		?>
	</p></div>
<?php endif; ?>

<?php if ( '' !== $gsss_role ) : ?>
	<div class="notice notice-warning inline"><p>
		<?php
		/* translators: %s: nom du rôle */
		echo esc_html( sprintf( __( 'Les inscriptions sont ouvertes et chaque nouveau compte reçoit le rôle « %s ».', 'graphin-simple-security-ssl' ), $gsss_role ) );
		?>
	</p></div>
<?php endif; ?>

<form class="gsss-card" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="gsss_save_hardening">
	<?php wp_nonce_field( 'gsss_save_hardening' ); ?>

	<ul class="gsss-options">
		<?php foreach ( $gsss_options as $gsss_key => $gsss_option ) : ?>
			<li class="gsss-option" id="gsss-opt-<?php echo esc_attr( $gsss_key ); ?>">
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
					<?php if ( $gsss_option['apache'] ) : ?>
						<span class="gsss-badge gsss-badge--info"><?php echo $gsss_apache ? esc_html__( 'Apache', 'graphin-simple-security-ssl' ) : esc_html__( 'Snippet Nginx', 'graphin-simple-security-ssl' ); ?></span>
					<?php endif; ?>
					<?php if ( $gsss_old && in_array( $gsss_key, $gsss_overlap, true ) ) : ?>
						<span class="gsss-badge gsss-badge--info"><?php esc_html_e( 'Déjà fait par Graph\'in Hardening', 'graphin-simple-security-ssl' ); ?></span>
					<?php endif; ?>
					<p class="description"><?php echo esc_html( $gsss_option['help'] ); ?></p>
					<?php if ( '' !== $gsss_option['warning'] ) : ?>
						<p class="description gsss-warning"><?php echo esc_html( $gsss_option['warning'] ); ?></p>
					<?php endif; ?>
				</div>
			</li>
		<?php endforeach; ?>
	</ul>

	<p><?php submit_button( __( 'Enregistrer', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?></p>
</form>

<?php if ( '' !== $gsss_snippet ) : ?>
	<section class="gsss-card">
		<h2><?php esc_html_e( 'Règles à ajouter à la configuration Nginx', 'graphin-simple-security-ssl' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Ces mesures ne peuvent pas s\'appliquer depuis PHP : collez ces lignes dans le bloc server du site, puis rechargez Nginx.', 'graphin-simple-security-ssl' ); ?></p>
		<textarea id="gsss-nginx-snippet" class="large-text code" rows="8" readonly><?php echo esc_textarea( $gsss_snippet ); ?></textarea>
		<p><button type="button" class="button" data-gsss-copy="gsss-nginx-snippet"><?php esc_html_e( 'Copier', 'graphin-simple-security-ssl' ); ?></button> <span class="gsss-copy-result" role="status" aria-live="polite"></span></p>
	</section>
<?php endif; ?>
