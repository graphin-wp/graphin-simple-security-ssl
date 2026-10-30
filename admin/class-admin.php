<?php
/**
 * Menus et pages d'administration.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Administration du plugin.
 */
class Admin {

	/**
	 * Suffixes de pages, pour ne charger les assets que chez nous.
	 *
	 * @var string[]
	 */
	private $page_hooks = array();

	/**
	 * Pages : slug => libellé. Le premier slug est la page parente.
	 *
	 * @return array
	 */
	public static function pages() {
		return array(
			'gsss'           => __( 'Tableau de bord', 'graphin-simple-security-ssl' ),
			'gsss-ssl'       => __( 'SSL', 'graphin-simple-security-ssl' ),
			'gsss-headers'   => __( 'En-têtes de sécurité', 'graphin-simple-security-ssl' ),
			'gsss-vulns'     => __( 'Vulnérabilités', 'graphin-simple-security-ssl' ),
			'gsss-hardening' => __( 'Durcissement', 'graphin-simple-security-ssl' ),
			'gsss-login'     => __( 'Connexion', 'graphin-simple-security-ssl' ),
			'gsss-settings'  => __( 'Réglages généraux', 'graphin-simple-security-ssl' ),
		);
	}

	/**
	 * Branche les hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'admin_menu', array( $this, 'add_menus' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Crée le menu et les sous-pages.
	 *
	 * @return void
	 */
	public function add_menus() {
		$pages = self::pages();
		$first = true;
		foreach ( $pages as $slug => $label ) {
			if ( $first ) {
				$this->page_hooks[] = add_menu_page(
					__( 'Graph\'in Security', 'graphin-simple-security-ssl' ),
					__( 'Graph\'in Security', 'graphin-simple-security-ssl' ),
					'manage_options',
					$slug,
					array( $this, 'render_page' ),
					'dashicons-shield',
					81
				);
				$first              = false;
			}
			$this->page_hooks[] = add_submenu_page( 'gsss', $label, $label, 'manage_options', $slug, array( $this, 'render_page' ) );
		}
	}

	/**
	 * Affiche la vue de la page demandée.
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Accès refusé.', 'graphin-simple-security-ssl' ), '', array( 'response' => 403 ) );
		}
		$pages = self::pages();
		$slug  = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'gsss'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Navigation en lecture seule.
		if ( ! isset( $pages[ $slug ] ) ) {
			$slug = 'gsss';
		}
		$title = $pages[ $slug ];
		$view  = GSSS_PATH . 'admin/views/' . ( 'gsss' === $slug ? 'dashboard' : substr( $slug, 5 ) ) . '.php';
		include GSSS_PATH . 'admin/views/layout.php';
	}

	/**
	 * Assets chargés uniquement sur les pages du plugin.
	 *
	 * @param string $hook_suffix Page admin courante.
	 * @return void
	 */
	public function enqueue_assets( $hook_suffix ) {
		if ( ! in_array( $hook_suffix, $this->page_hooks, true ) ) {
			return;
		}
		wp_enqueue_style( 'gsss-admin', GSSS_URL . 'assets/admin.css', array(), GSSS_VERSION );
		wp_enqueue_script( 'gsss-admin', GSSS_URL . 'assets/admin.js', array(), GSSS_VERSION, true );
	}
}
