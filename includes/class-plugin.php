<?php
/**
 * Chargement des modules, activation et désactivation.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Classe principale du plugin.
 */
class Plugin {

	/**
	 * Instance unique.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Modules chargés, indexés par identifiant.
	 *
	 * @var Modules\Module[]
	 */
	private $modules = array();

	/**
	 * Retourne l'instance unique.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Démarre le plugin : modules, admin, mises à jour.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );
		add_action( 'plugins_loaded', array( __NAMESPACE__ . '\Logger', 'maybe_upgrade' ), 5 );
		add_action( 'plugins_loaded', array( $this, 'load_modules' ), 20 );
		add_action( 'gsss_deactivate', array( __NAMESPACE__ . '\Htaccess', 'remove_all' ) );
		add_action( 'gsss_deactivate', array( __NAMESPACE__ . '\Modules\Vulnerabilities', 'clear_schedule' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( GSSS_FILE ), array( $this, 'action_links' ) );

		( new Admin\Admin() )->register_hooks();
		$this->init_updater();
	}

	/**
	 * Mode secours : aucun module, seulement un bandeau dans l'admin.
	 *
	 * @return void
	 */
	public static function boot_safe_mode() {
		add_action( 'admin_notices', array( __CLASS__, 'safe_mode_notice' ) );
		// Le mode secours retire aussi le bloc .htaccess, sans toucher à la base de données.
		add_action( 'admin_init', array( __NAMESPACE__ . '\Htaccess', 'remove_if_present' ) );
	}

	/**
	 * Bandeau du mode secours.
	 *
	 * @return void
	 */
	public static function safe_mode_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Graph\'in Security : mode secours actif.', 'graphin-simple-security-ssl' ) . '</strong> ';
		echo esc_html__( 'La constante GSSS_SAFE_MODE est définie dans wp-config.php : aucune règle du plugin n\'est appliquée. Retirez-la pour reprendre un fonctionnement normal.', 'graphin-simple-security-ssl' );
		echo '</p></div>';
	}

	/**
	 * Charge la traduction.
	 *
	 * @return void
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'graphin-simple-security-ssl', false, dirname( plugin_basename( GSSS_FILE ) ) . '/languages' );
	}

	/**
	 * Instancie les modules déclarés. Liste vide au module 1.
	 *
	 * @return void
	 */
	public function load_modules() {
		/**
		 * Classes de modules à charger (nom complet de classe).
		 *
		 * @param string[] $classes Classes qui étendent Modules\Module.
		 */
		$classes = apply_filters( 'gsss_module_classes', array( __NAMESPACE__ . '\Modules\Vulnerabilities' ) );
		foreach ( $classes as $class ) {
			if ( is_subclass_of( $class, '\Graphin\SimpleSecurity\Modules\Module' ) ) {
				$module                         = new $class();
				$this->modules[ $module->id() ] = $module;
				if ( $module->is_enabled() ) {
					$module->register_hooks();
				}
			}
		}
	}

	/**
	 * Modules chargés.
	 *
	 * @return Modules\Module[]
	 */
	public function modules() {
		return $this->modules;
	}

	/**
	 * Lien « Réglages » dans la liste des extensions.
	 *
	 * @param string[] $links Liens existants.
	 * @return string[]
	 */
	public function action_links( $links ) {
		$url = admin_url( 'admin.php?page=gsss' );
		array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Réglages', 'graphin-simple-security-ssl' ) . '</a>' );
		return $links;
	}

	/**
	 * Branche Plugin Update Checker sur le dépôt GitHub (releases taguées).
	 *
	 * @return void
	 */
	private function init_updater() {
		$loader = GSSS_PATH . 'vendor/plugin-update-checker/plugin-update-checker.php';
		if ( ! is_readable( $loader ) ) {
			return;
		}
		require_once $loader;
		$checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker( GSSS_REPO_URL, GSSS_FILE, 'graphin-simple-security-ssl' );
		$checker->getVcsApi()->enableReleaseAssets();
	}

	/**
	 * Activation : rien n'est appliqué, on note seulement la version.
	 *
	 * @return void
	 */
	public static function activate() {
		update_option( 'gsss_version', GSSS_VERSION, false );
		Logger::install();
	}

	/**
	 * Désactivation : point d'accroche pour retirer règles .htaccess et crons.
	 * Les réglages sont conservés.
	 *
	 * @return void
	 */
	public static function deactivate() {
		/**
		 * Les modules y retirent leurs règles et planifications.
		 */
		do_action( 'gsss_deactivate' );
	}
}
