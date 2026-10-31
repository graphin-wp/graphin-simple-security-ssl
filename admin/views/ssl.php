<?php
/**
 * Vue : SSL.
 *
 * @package Graphin\SimpleSecurity
 */

use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Modules\Ssl;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'is_plugin_active' ) ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

$gsss_settings  = Settings::all();
$gsss_notice    = isset( $_GET['gsss_notice'] ) ? sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
$gsss_enabled   = (bool) $gsss_settings['ssl_enabled'];
$gsss_detection = Ssl::last_detection();
$gsss_constants = Ssl::constants_block();
$gsss_can       = $gsss_detection && $gsss_detection['ok'] && ! $gsss_constants && ! is_multisite();
$gsss_host      = Ssl::host();
$gsss_apache    = 'apache' === $gsss_settings['server_mode'] && Htaccess::is_writable();
$gsss_messages  = array(
	'saved'          => array( 'success', __( 'Réglages enregistrés.', 'graphin-simple-security-ssl' ) ),
	'htaccess_error' => array( 'warning', __( 'Réglages enregistrés, mais .htaccess n\'a pas pu être mis à jour : la redirection et HSTS passent par PHP. Voir le journal.', 'graphin-simple-security-ssl' ) ),
	'www_mismatch'   => array( 'error', __( 'Ce choix ne correspond pas à l\'adresse du site et ferait boucler la redirection avec celle de WordPress. Changez d\'abord l\'adresse dans Réglages > Général.', 'graphin-simple-security-ssl' ) ),
	'ssl_enabled'    => array( 'success', __( 'SSL activé. Vérifiez quelques pages du site, puis cochez les options utiles ci-dessous.', 'graphin-simple-security-ssl' ) ),
	'ssl_detect'     => array( 'error', __( 'Aucun certificat valide ne répond en https : SSL non activé.', 'graphin-simple-security-ssl' ) ),
	'ssl_constants'  => array( 'error', __( 'WP_HOME ou WP_SITEURL sont fixées en http dans wp-config.php : passez-les en https à la main, puis revenez ici.', 'graphin-simple-security-ssl' ) ),
	'ssl_multisite'  => array( 'error', __( 'Le multisite n\'est pas pris en charge par ce module.', 'graphin-simple-security-ssl' ) ),
	'ssl_rollback'   => array( 'error', __( 'Le site ne répondait plus avec les nouvelles règles (boucle de redirection ?) : tout est revenu comme avant. Voir le journal.', 'graphin-simple-security-ssl' ) ),
	'ssl_reverted'   => array( 'warning', __( 'Retour en HTTP effectué. Les navigateurs qui ont reçu HSTS restent en https jusqu\'à son expiration.', 'graphin-simple-security-ssl' ) ),
);
?>
<?php if ( isset( $gsss_messages[ $gsss_notice ] ) ) : ?>
	<div class="notice notice-<?php echo esc_attr( $gsss_messages[ $gsss_notice ][0] ); ?> inline"><p><?php echo esc_html( $gsss_messages[ $gsss_notice ][1] ); ?></p></div>
<?php endif; ?>

<?php if ( is_plugin_active( 'graphin-hardening/graphin-hardening.php' ) ) : ?>
	<div class="notice notice-info inline"><p><?php esc_html_e( 'Graph\'in Hardening est actif et envoie déjà HSTS. Pour éviter un en-tête en double, cochez HSTS ici puis désactivez-le.', 'graphin-simple-security-ssl' ); ?></p></div>
<?php endif; ?>

<section class="gsss-card">
	<h2><?php esc_html_e( 'Certificat', 'graphin-simple-security-ssl' ); ?></h2>
	<?php if ( null === $gsss_detection ) : ?>
		<p><?php esc_html_e( 'Pas encore vérifié.', 'graphin-simple-security-ssl' ); ?></p>
	<?php else : ?>
		<p>
			<span class="<?php echo $gsss_detection['ok'] ? 'gsss-ok' : 'gsss-ko'; ?>"><?php echo $gsss_detection['ok'] ? esc_html__( 'Valide', 'graphin-simple-security-ssl' ) : esc_html__( 'Non valide', 'graphin-simple-security-ssl' ); ?></span>
			<?php echo esc_html( $gsss_detection['message'] ); ?>
		</p>
		<?php if ( $gsss_detection['expires'] ) : ?>
			<p>
				<?php
				/* translators: %s: date */
				echo esc_html( sprintf( __( 'Expire le %s.', 'graphin-simple-security-ssl' ), wp_date( get_option( 'date_format' ), $gsss_detection['expires'] ) ) );
				?>
				<?php if ( $gsss_detection['expires'] < time() + 14 * DAY_IN_SECONDS ) : ?>
					<span class="gsss-warning"><?php esc_html_e( 'Moins de 14 jours : vérifiez le renouvellement automatique chez l\'hébergeur.', 'graphin-simple-security-ssl' ); ?></span>
				<?php endif; ?>
			</p>
		<?php endif; ?>
		<p class="description">
			<?php
			/* translators: %s: date et heure */
			echo esc_html( sprintf( __( 'Dernière vérification : %s', 'graphin-simple-security-ssl' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $gsss_detection['checked'] ) ) );
			?>
		</p>
	<?php endif; ?>
	<p><button type="button" class="button" id="gsss-ssl-detect"><?php esc_html_e( 'Revérifier', 'graphin-simple-security-ssl' ); ?></button> <span id="gsss-ssl-detect-status" role="status" aria-live="polite"></span></p>
</section>

<section class="gsss-card">
	<h2><?php echo $gsss_enabled ? esc_html__( 'SSL activé', 'graphin-simple-security-ssl' ) : esc_html__( 'Activer le SSL', 'graphin-simple-security-ssl' ); ?></h2>
	<p>
		<?php
		/* translators: 1: adresse du site, 2: adresse de WordPress */
		echo esc_html( sprintf( __( 'Adresse du site : %1$s. Adresse de WordPress : %2$s.', 'graphin-simple-security-ssl' ), get_option( 'home' ), get_option( 'siteurl' ) ) );
		?>
	</p>
	<?php if ( ! $gsss_enabled ) : ?>
		<p class="description"><?php esc_html_e( 'Passe les adresses du site en https (si elles ne le sont pas déjà) et redirige en 301 toutes les pages demandées en http. Les envois de formulaires ne sont pas redirigés. Rien n\'est fait si le certificat n\'est pas valide.', 'graphin-simple-security-ssl' ); ?></p>
		<?php if ( $gsss_constants ) : ?>
			<p class="gsss-warning"><?php echo esc_html( $gsss_messages['ssl_constants'][1] ); ?></p>
		<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-gsss-confirm-msg="<?php esc_attr_e( 'Activer le SSL ? Gardez cet onglet ouvert : en cas de souci, la constante GSSS_SAFE_MODE dans wp-config.php retire les règles.', 'graphin-simple-security-ssl' ); ?>">
			<input type="hidden" name="action" value="gsss_ssl_enable">
			<?php wp_nonce_field( 'gsss_ssl_enable' ); ?>
			<button type="submit" class="button button-primary" <?php disabled( ! $gsss_can ); ?>><?php esc_html_e( 'Activer le SSL', 'graphin-simple-security-ssl' ); ?></button>
			<?php if ( ! $gsss_can ) : ?>
				<span class="description"><?php esc_html_e( 'Disponible quand la vérification du certificat réussit.', 'graphin-simple-security-ssl' ); ?></span>
			<?php endif; ?>
		</form>
	<?php else : ?>
		<p class="description">
			<?php
			echo Ssl::redirect_via_php() ? esc_html__( 'La redirection vers https passe par PHP.', 'graphin-simple-security-ssl' ) : esc_html__( 'La redirection vers https est écrite dans .htaccess.', 'graphin-simple-security-ssl' );
			if ( $gsss_settings['ssl_hsts'] ) {
				echo ' ' . ( Ssl::hsts_via_php() ? esc_html__( 'HSTS passe par PHP.', 'graphin-simple-security-ssl' ) : esc_html__( 'HSTS est écrit dans .htaccess.', 'graphin-simple-security-ssl' ) );
			}
			?>
		</p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-gsss-confirm-msg="<?php esc_attr_e( 'Revenir en HTTP ? La redirection et HSTS sont retirés, et les adresses changées par le plugin repassent en http. Les navigateurs qui ont reçu HSTS resteront en https jusqu\'à son expiration (un an).', 'graphin-simple-security-ssl' ); ?>">
			<input type="hidden" name="action" value="gsss_ssl_revert">
			<?php wp_nonce_field( 'gsss_ssl_revert' ); ?>
			<button type="submit" class="button"><?php esc_html_e( 'Revenir en HTTP', 'graphin-simple-security-ssl' ); ?></button>
		</form>
	<?php endif; ?>
</section>

<form class="gsss-card" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="gsss_ssl_save">
	<?php wp_nonce_field( 'gsss_ssl_save' ); ?>
	<h2><?php esc_html_e( 'Options', 'graphin-simple-security-ssl' ); ?></h2>
	<?php if ( ! $gsss_enabled ) : ?>
		<p class="description"><?php esc_html_e( 'Ces options n\'agissent qu\'une fois le SSL activé.', 'graphin-simple-security-ssl' ); ?></p>
	<?php endif; ?>

	<ul class="gsss-options">
		<li class="gsss-option">
			<div class="gsss-option__body">
				<label for="gsss-ssl-www"><strong><?php esc_html_e( 'Variante www', 'graphin-simple-security-ssl' ); ?></strong></label>
				<p>
					<select id="gsss-ssl-www" name="ssl_www">
						<option value="none" <?php selected( $gsss_settings['ssl_www'], 'none' ); ?>><?php esc_html_e( 'Aucune redirection', 'graphin-simple-security-ssl' ); ?></option>
						<option value="www" <?php selected( $gsss_settings['ssl_www'], 'www' ); ?> <?php disabled( ! Ssl::www_matches( 'www' ) ); ?>><?php esc_html_e( 'Forcer www', 'graphin-simple-security-ssl' ); ?></option>
						<option value="non-www" <?php selected( $gsss_settings['ssl_www'], 'non-www' ); ?> <?php disabled( ! Ssl::www_matches( 'non-www' ) ); ?>><?php esc_html_e( 'Forcer sans www', 'graphin-simple-security-ssl' ); ?></option>
					</select>
				</p>
				<p class="description">
					<?php
					/* translators: %s: hôte du site */
					echo esc_html( sprintf( __( 'Redirige l\'autre variante vers %s, en un seul saut avec le passage en https. Seul le choix qui correspond à l\'adresse du site est proposé.', 'graphin-simple-security-ssl' ), $gsss_host ) );
					?>
				</p>
				<p class="description gsss-warning"><?php esc_html_e( 'Le certificat doit couvrir les deux variantes, sinon la redirection depuis l\'autre variante affiche une erreur de certificat.', 'graphin-simple-security-ssl' ); ?></p>
			</div>
		</li>

		<?php
		$gsss_switches = array(
			'ssl_mixed_front'     => array(
				__( 'Corriger le contenu mixte sur le site', 'graphin-simple-security-ssl' ),
				__( 'Réécrit en https les adresses http du site (images, scripts, styles, liens, srcset, url() CSS) au moment d\'envoyer la page. Les autres domaines ne sont pas modifiés : Upgrade Insecure Requests (page En-têtes) s\'en charge.', 'graphin-simple-security-ssl' ),
				'',
			),
			'ssl_mixed_admin'     => array(
				__( 'Corriger le contenu mixte dans l\'administration', 'graphin-simple-security-ssl' ),
				__( 'Même correction sur les pages d\'administration.', 'graphin-simple-security-ssl' ),
				__( 'À cocher seulement si l\'administration affiche des alertes de contenu mixte.', 'graphin-simple-security-ssl' ),
			),
			'ssl_hsts'            => array(
				__( 'HSTS (Strict-Transport-Security)', 'graphin-simple-security-ssl' ),
				__( 'Le navigateur retient pendant un an que le site ne s\'ouvre qu\'en https, sans jamais repasser par http.', 'graphin-simple-security-ssl' ),
				__( 'Engagement d\'un an : si le certificat cesse de fonctionner, les visiteurs déjà venus ne pourront plus ouvrir le site, même après « Revenir en HTTP ».', 'graphin-simple-security-ssl' ),
			),
			'ssl_hsts_subdomains' => array(
				__( 'HSTS : inclure les sous-domaines', 'graphin-simple-security-ssl' ),
				__( 'Ajoute includeSubDomains : la règle vaut aussi pour tous les sous-domaines.', 'graphin-simple-security-ssl' ),
				__( 'Tous les sous-domaines (webmail, extranet, préproduction) doivent avoir un certificat valide.', 'graphin-simple-security-ssl' ),
			),
			'ssl_hsts_preload'    => array(
				__( 'HSTS : preload', 'graphin-simple-security-ssl' ),
				__( 'Ajoute preload (et includeSubDomains, exigé par les navigateurs). L\'inscription sur hstspreload.org reste une démarche manuelle.', 'graphin-simple-security-ssl' ),
				__( 'Une fois le domaine inscrit sur la liste des navigateurs, en sortir prend des mois. Ne cochez que pour un domaine qui restera en https.', 'graphin-simple-security-ssl' ),
			),
		);
		foreach ( $gsss_switches as $gsss_key => $gsss_switch ) :
			?>
			<li class="gsss-option">
				<label class="gsss-switch">
					<input type="checkbox" name="<?php echo esc_attr( $gsss_key ); ?>" value="1" <?php checked( (int) $gsss_settings[ $gsss_key ], 1 ); ?>>
					<span class="gsss-switch__slider" aria-hidden="true"></span>
					<span class="screen-reader-text"><?php echo esc_html( $gsss_switch[0] ); ?></span>
				</label>
				<div class="gsss-option__body">
					<strong><?php echo esc_html( $gsss_switch[0] ); ?></strong>
					<p class="description"><?php echo esc_html( $gsss_switch[1] ); ?></p>
					<?php if ( '' !== $gsss_switch[2] ) : ?>
						<p class="description gsss-warning"><?php echo esc_html( $gsss_switch[2] ); ?></p>
					<?php endif; ?>
				</div>
			</li>
		<?php endforeach; ?>
	</ul>

	<p><?php submit_button( __( 'Enregistrer', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?></p>
</form>

<?php if ( ! $gsss_apache ) : ?>
	<section class="gsss-card">
		<h2><?php esc_html_e( 'Règles pour Nginx', 'graphin-simple-security-ssl' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Le plugin redirige par PHP. Pour le faire au niveau du serveur, ajoutez ces lignes à sa configuration.', 'graphin-simple-security-ssl' ); ?></p>
		<pre class="gsss-code"><?php echo esc_html( ( new Ssl() )->nginx_rules() ); ?></pre>
	</section>
<?php endif; ?>
