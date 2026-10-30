<?php
/**
 * Plugin Name: Graph'in Simple Security SSL
 * Plugin URI: https://github.com/graphin-wp/graphin-simple-security-ssl
 * Description: Sécurité WordPress sobre pour les sites clients Graph'in : SSL, en-têtes, vulnérabilités, durcissement, connexion et 2FA. Aucune option n'agit tant qu'elle n'est pas cochée.
 * Version: 0.3.0
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: Graph'in
 * Author URI: https://graph-in.fr
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: graphin-simple-security-ssl
 * Domain Path: /languages
 *
 * @package Graphin\SimpleSecurity
 */

defined( 'ABSPATH' ) || exit;

define( 'GSSS_VERSION', '0.3.0' );
define( 'GSSS_FILE', __FILE__ );
define( 'GSSS_PATH', plugin_dir_path( __FILE__ ) );
define( 'GSSS_URL', plugin_dir_url( __FILE__ ) );

// Adresse de l'agence qui reçoit les alertes (modifiable dans les réglages par un administrateur).
if ( ! defined( 'GSSS_AGENCY_EMAIL' ) ) {
	define( 'GSSS_AGENCY_EMAIL', 'guillaume@graph-in.fr' );
}

// Dépôt GitHub public des mises à jour.
if ( ! defined( 'GSSS_REPO_URL' ) ) {
	define( 'GSSS_REPO_URL', 'https://github.com/graphin-wp/graphin-simple-security-ssl/' );
}

require_once GSSS_PATH . 'includes/class-plugin.php';
require_once GSSS_PATH . 'includes/class-htaccess.php';

// Mode secours : vérifié en tout premier, avant tout module.
if ( defined( 'GSSS_SAFE_MODE' ) && GSSS_SAFE_MODE ) {
	\Graphin\SimpleSecurity\Plugin::boot_safe_mode();
	return;
}

require_once GSSS_PATH . 'includes/class-settings.php';
require_once GSSS_PATH . 'includes/class-logger.php';
require_once GSSS_PATH . 'includes/class-mailer.php';
require_once GSSS_PATH . 'includes/class-vuln-scanner.php';
require_once GSSS_PATH . 'includes/modules/class-module.php';
require_once GSSS_PATH . 'includes/modules/class-vulnerabilities.php';
require_once GSSS_PATH . 'admin/class-admin.php';

register_activation_hook( __FILE__, array( '\Graphin\SimpleSecurity\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( '\Graphin\SimpleSecurity\Plugin', 'deactivate' ) );

\Graphin\SimpleSecurity\Plugin::instance()->boot();
