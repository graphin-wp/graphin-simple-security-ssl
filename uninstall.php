<?php
/**
 * Suppression du plugin : retire le bloc .htaccess, les options, transients, tables,
 * métadonnées utilisateur et crons. Les adresses du site restent en https : revenir en http
 * casserait un site dont le certificat fonctionne.
 *
 * @package Graphin\SimpleSecurity
 */

// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Classes chargées pour leurs constantes et noms de tables : ces fichiers ne déclarent que des classes.
require_once __DIR__ . '/includes/class-htaccess.php';
require_once __DIR__ . '/includes/class-logger.php';
require_once __DIR__ . '/includes/login/class-login-limiter.php';
require_once __DIR__ . '/includes/modules/class-module.php';
require_once __DIR__ . '/includes/modules/class-vulnerabilities.php';

use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Login\LoginLimiter;
use Graphin\SimpleSecurity\Modules\Vulnerabilities;

// Le plugin a pu être supprimé sans passer par la désactivation (fichiers effacés à la main).
Htaccess::remove_all();
foreach ( array( Htaccess::path(), Htaccess::uploads_path() ) as $gsss_file ) {
	if ( '' !== $gsss_file ) {
		wp_delete_file( $gsss_file . '.gsss-backup' );
	}
}

foreach ( array( Vulnerabilities::HOOK_DAILY, Vulnerabilities::HOOK_CONTINUE, Vulnerabilities::HOOK_RETRY, LoginLimiter::HOOK_PURGE ) as $gsss_hook ) {
	wp_clear_scheduled_hook( $gsss_hook );
}

global $wpdb;

// Options et transients : tout ce qui porte le préfixe, sans liste à tenir à jour.
foreach ( array( 'gsss_', '_transient_gsss_', '_transient_timeout_gsss_' ) as $gsss_prefix ) {
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( $gsss_prefix ) . '%' ) );
}

// Métadonnées utilisateur (2FA : secret, codes de secours, appareils de confiance).
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( 'gsss_' ) . '%' ) );

foreach ( array( Logger::table(), LoginLimiter::table() ) as $gsss_table ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$gsss_table}" );
}

// Requêtes directes : le cache objet (options, métadonnées) doit repartir de la base.
wp_cache_flush();
