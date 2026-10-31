<?php
/**
 * Vue : tableau de bord.
 *
 * @package Graphin\SimpleSecurity
 */

use Graphin\SimpleSecurity\Dashboard;
use Graphin\SimpleSecurity\Modules\Ssl;
use Graphin\SimpleSecurity\Settings;
use Graphin\SimpleSecurity\VulnScanner;

defined( 'ABSPATH' ) || exit;

$gsss_notice     = isset( $_GET['gsss_notice'] ) ? sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
$gsss_score      = Dashboard::score();
$gsss_todo       = wp_list_filter( $gsss_score['items'], array( 'done' => false ) );
$gsss_to_apply   = array_diff_key( $gsss_todo, array( 'ssl_enabled' => true ) );
$gsss_hardening  = Dashboard::hardening_active();
$gsss_mixed      = Dashboard::mixed_content_risk();
$gsss_duplicates = Dashboard::duplicates();
$gsss_ssl_on     = (bool) Settings::get( 'ssl_enabled' );
$gsss_detection  = Ssl::last_detection();
$gsss_vulns      = VulnScanner::results();
$gsss_update     = Dashboard::update_available();
$gsss_date       = get_option( 'date_format' );
$gsss_messages   = array(
	'recommended'          => array( 'success', __( 'Réglages recommandés appliqués.', 'graphin-simple-security-ssl' ) ),
	'rollback'             => array( 'error', __( 'Les nouvelles règles .htaccess rendaient le site inaccessible : tout a été remis comme avant. Voir le journal dans les réglages généraux.', 'graphin-simple-security-ssl' ) ),
	'htaccess_error'       => array( 'warning', __( 'Réglages enregistrés, mais .htaccess n\'a pas pu être mis à jour. Voir le journal dans les réglages généraux.', 'graphin-simple-security-ssl' ) ),
	'hardening_done'       => array( 'success', __( 'Graph\'in Hardening est repris et désactivé. Le SSL et HSTS sont actifs ici.', 'graphin-simple-security-ssl' ) ),
	'hardening_done_http'  => array( 'success', __( 'Graph\'in Hardening est repris et désactivé. Le site n\'est pas en https : HSTS n\'est pas envoyé.', 'graphin-simple-security-ssl' ) ),
	'hardening_done_nossl' => array( 'warning', __( 'Graph\'in Hardening est repris et désactivé, mais le SSL n\'a pas pu être activé : HSTS n\'est plus envoyé. Voir la page SSL.', 'graphin-simple-security-ssl' ) ),
	'hardening_absent'     => array( 'info', __( 'Graph\'in Hardening n\'est pas actif : rien à reprendre.', 'graphin-simple-security-ssl' ) ),
	'imported'             => array( 'success', __( 'Réglages importés. L\'adresse de connexion, la liste blanche, l\'email du client et l\'activation du SSL restent ceux de ce site.', 'graphin-simple-security-ssl' ) ),
	'import_invalid'       => array( 'error', __( 'Fichier refusé : choisissez un export de Graph\'in Security (fichier .json de 64 Ko au plus).', 'graphin-simple-security-ssl' ) ),
);
?>
<?php if ( isset( $gsss_messages[ $gsss_notice ] ) ) : ?>
	<div class="notice notice-<?php echo esc_attr( $gsss_messages[ $gsss_notice ][0] ); ?> inline"><p><?php echo esc_html( $gsss_messages[ $gsss_notice ][1] ); ?></p></div>
<?php endif; ?>

<?php if ( $gsss_hardening ) : ?>
	<section class="gsss-card gsss-card--highlight">
		<h2><?php esc_html_e( 'Reprendre Graph\'in Hardening', 'graphin-simple-security-ssl' ); ?></h2>
		<p><?php esc_html_e( 'Graph\'in Hardening est actif. Ce plugin fait la même chose : en-têtes de sécurité, XML-RPC fermé, test OPcache masqué. Le bouton coche les réglages équivalents ici, vérifie qu\'ils sont servis, puis désactive Graph\'in Hardening.', 'graphin-simple-security-ssl' ); ?></p>
		<p class="description">
			<?php
			if ( Dashboard::site_is_https() ) {
				esc_html_e( 'Le site est en https : le SSL est activé dans la foulée pour garder HSTS.', 'graphin-simple-security-ssl' );
			} else {
				esc_html_e( 'Le site n\'est pas en https : HSTS ne sera pas repris.', 'graphin-simple-security-ssl' );
			}
			?>
			<?php esc_html_e( 'X-XSS-Protection passe à 0, la valeur conseillée aujourd\'hui.', 'graphin-simple-security-ssl' ); ?>
		</p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-gsss-confirm-msg="<?php esc_attr_e( 'Reprendre les réglages de Graph\'in Hardening puis le désactiver ?', 'graphin-simple-security-ssl' ); ?>">
			<input type="hidden" name="action" value="gsss_take_over_hardening">
			<?php wp_nonce_field( 'gsss_take_over_hardening' ); ?>
			<?php submit_button( __( 'Reprendre et désactiver Graph\'in Hardening', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?>
		</form>
	</section>
<?php endif; ?>

<section class="gsss-card">
	<h2><?php esc_html_e( 'Score de sécurité', 'graphin-simple-security-ssl' ); ?></h2>
	<div class="gsss-score gsss-score--<?php echo esc_attr( $gsss_score['level'] ); ?>">
		<span class="gsss-score__value"><?php echo esc_html( $gsss_score['percent'] ); ?> %</span>
		<span class="gsss-score__bar" aria-hidden="true"><span style="width: <?php echo esc_attr( $gsss_score['percent'] ); ?>%"></span></span>
	</div>
	<p class="description">
		<?php
		/* translators: 1: points en place, 2: total */
		echo esc_html( sprintf( __( '%1$d points recommandés en place sur %2$d.', 'graphin-simple-security-ssl' ), $gsss_score['done'], $gsss_score['total'] ) );
		?>
	</p>

	<?php if ( ! empty( $gsss_todo ) || $gsss_mixed ) : ?>
		<h3><?php esc_html_e( 'À faire', 'graphin-simple-security-ssl' ); ?></h3>
		<ul class="gsss-todo">
			<?php foreach ( $gsss_todo as $gsss_key => $gsss_item ) : ?>
				<li><a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $gsss_item['page'] ) . '#gsss-opt-' . $gsss_key ); ?>"><?php echo esc_html( $gsss_item['label'] ); ?></a></li>
			<?php endforeach; ?>
			<?php if ( $gsss_mixed ) : ?>
				<li><a href="<?php echo esc_url( admin_url( 'admin.php?page=gsss-ssl' ) . '#gsss-opt-ssl_mixed_front' ); ?>"><?php esc_html_e( 'Corriger le contenu mixte (conseillé une fois le SSL actif)', 'graphin-simple-security-ssl' ); ?></a></li>
			<?php endif; ?>
		</ul>
	<?php endif; ?>

	<?php if ( ! empty( $gsss_to_apply ) ) : ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-gsss-confirm-msg="<?php esc_attr_e( 'Cocher tous les réglages recommandés ? Le SSL et la double authentification ne sont pas concernés.', 'graphin-simple-security-ssl' ); ?>">
			<input type="hidden" name="action" value="gsss_apply_recommended">
			<?php wp_nonce_field( 'gsss_apply_recommended' ); ?>
			<?php submit_button( __( 'Appliquer les réglages recommandés', 'graphin-simple-security-ssl' ), 'primary', 'submit', false ); ?>
		</form>
		<p class="description"><?php esc_html_e( 'Le SSL s\'active depuis sa page, après la vérification du certificat. Votre IP est ajoutée à la liste blanche de la limitation des connexions.', 'graphin-simple-security-ssl' ); ?></p>
	<?php endif; ?>
</section>

<?php if ( ! empty( $gsss_duplicates ) ) : ?>
	<section class="gsss-card">
		<h2><?php esc_html_e( 'Extensions en doublon', 'graphin-simple-security-ssl' ); ?></h2>
		<p><?php esc_html_e( 'Ces extensions font une partie du travail de ce plugin. Une fois les réglages équivalents cochés ici, désactivez-les pour éviter les blocages en double.', 'graphin-simple-security-ssl' ); ?></p>
		<ul class="gsss-todo">
			<?php foreach ( $gsss_duplicates as $gsss_name ) : ?>
				<li><?php echo esc_html( $gsss_name ); ?></li>
			<?php endforeach; ?>
		</ul>
		<p><a class="button" href="<?php echo esc_url( admin_url( 'plugins.php?plugin_status=active' ) ); ?>"><?php esc_html_e( 'Ouvrir la page Extensions', 'graphin-simple-security-ssl' ); ?></a></p>
	</section>
<?php endif; ?>

<section class="gsss-card">
	<h2><?php esc_html_e( 'État', 'graphin-simple-security-ssl' ); ?></h2>
	<table class="widefat striped gsss-status">
		<tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'SSL', 'graphin-simple-security-ssl' ); ?></th>
				<td>
					<?php if ( $gsss_ssl_on ) : ?>
						<span class="gsss-ok"><?php esc_html_e( 'Actif', 'graphin-simple-security-ssl' ); ?></span>
					<?php else : ?>
						<span class="gsss-ko"><?php esc_html_e( 'Inactif', 'graphin-simple-security-ssl' ); ?></span>
					<?php endif; ?>
					<?php if ( $gsss_detection && ! empty( $gsss_detection['expires'] ) ) : ?>
						<?php
						$gsss_days = (int) floor( ( (int) $gsss_detection['expires'] - time() ) / DAY_IN_SECONDS );
						/* translators: 1: date, 2: nombre de jours */
						$gsss_expiry = sprintf( __( 'Certificat valable jusqu\'au %1$s (%2$d jours).', 'graphin-simple-security-ssl' ), wp_date( $gsss_date, (int) $gsss_detection['expires'] ), $gsss_days );
						?>
						<br><span class="<?php echo $gsss_days < 14 ? 'gsss-ko' : ''; ?>"><?php echo esc_html( $gsss_expiry ); ?></span>
					<?php elseif ( $gsss_detection && ! $gsss_detection['ok'] ) : ?>
						<br><?php echo esc_html( $gsss_detection['message'] ); ?>
					<?php endif; ?>
					<br><a href="<?php echo esc_url( admin_url( 'admin.php?page=gsss-ssl' ) ); ?>"><?php esc_html_e( 'Page SSL', 'graphin-simple-security-ssl' ); ?></a>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Vulnérabilités', 'graphin-simple-security-ssl' ); ?></th>
				<td>
					<?php if ( $gsss_vulns['time'] ) : ?>
						<?php
						$gsss_found = count( $gsss_vulns['findings'] );
						/* translators: 1: date, 2: nombre de failles */
						$gsss_scan = sprintf( _n( 'Dernier scan le %1$s : %2$d faille.', 'Dernier scan le %1$s : %2$d failles.', $gsss_found, 'graphin-simple-security-ssl' ), wp_date( $gsss_date, (int) $gsss_vulns['time'] ), $gsss_found );
						?>
						<span class="<?php echo $gsss_found ? 'gsss-ko' : 'gsss-ok'; ?>"><?php echo esc_html( $gsss_scan ); ?></span>
					<?php else : ?>
						<?php esc_html_e( 'Aucun scan pour l\'instant.', 'graphin-simple-security-ssl' ); ?>
					<?php endif; ?>
					<br><a href="<?php echo esc_url( admin_url( 'admin.php?page=gsss-vulns' ) ); ?>"><?php esc_html_e( 'Page Vulnérabilités', 'graphin-simple-security-ssl' ); ?></a>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Version du plugin', 'graphin-simple-security-ssl' ); ?></th>
				<td>
					<?php echo esc_html( GSSS_VERSION ); ?>
					<?php if ( '' !== $gsss_update ) : ?>
						<?php /* translators: %s: numéro de version */ ?>
						<br><a class="gsss-ko" href="<?php echo esc_url( admin_url( 'plugins.php' ) ); ?>"><?php echo esc_html( sprintf( __( 'Mise à jour disponible : %s', 'graphin-simple-security-ssl' ), $gsss_update ) ); ?></a>
					<?php else : ?>
						<br><span class="gsss-ok"><?php esc_html_e( 'À jour', 'graphin-simple-security-ssl' ); ?></span>
					<?php endif; ?>
				</td>
			</tr>
		</tbody>
	</table>
</section>

<section class="gsss-card">
	<h2><?php esc_html_e( 'Exporter ou importer les réglages', 'graphin-simple-security-ssl' ); ?></h2>
	<p class="description"><?php esc_html_e( 'Pour reprendre la configuration d\'un site sur un autre. L\'adresse de connexion, la liste blanche, l\'email du client et l\'activation du SSL ne sont pas exportés. La politique CSP repart en rapport seulement.', 'graphin-simple-security-ssl' ); ?></p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<input type="hidden" name="action" value="gsss_export">
		<?php wp_nonce_field( 'gsss_export' ); ?>
		<?php submit_button( __( 'Exporter (.json)', 'graphin-simple-security-ssl' ), 'secondary', 'submit', false ); ?>
	</form>
	<form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-gsss-confirm-msg="<?php esc_attr_e( 'Remplacer les réglages de ce site par ceux du fichier ?', 'graphin-simple-security-ssl' ); ?>">
		<input type="hidden" name="action" value="gsss_import">
		<?php wp_nonce_field( 'gsss_import' ); ?>
		<p>
			<label for="gsss-import-file"><?php esc_html_e( 'Fichier à importer', 'graphin-simple-security-ssl' ); ?></label><br>
			<input type="file" id="gsss-import-file" name="gsss_file" accept=".json,application/json" required>
		</p>
		<?php submit_button( __( 'Importer', 'graphin-simple-security-ssl' ), 'secondary', 'submit', false ); ?>
	</form>
</section>
