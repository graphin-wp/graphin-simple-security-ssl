<?php
/**
 * Menus et pages d'administration.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Admin;

use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Mailer;
use Graphin\SimpleSecurity\Modules\Hardening;
use Graphin\SimpleSecurity\Modules\Vulnerabilities;
use Graphin\SimpleSecurity\Settings;
use Graphin\SimpleSecurity\VulnScanner;

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
		add_action( 'admin_post_gsss_save_settings', array( $this, 'save_settings' ) );
		add_action( 'wp_ajax_gsss_send_test_mail', array( $this, 'ajax_send_test_mail' ) );
		add_action( 'admin_post_gsss_save_vulns', array( $this, 'save_vulns' ) );
		add_action( 'admin_post_gsss_save_hardening', array( $this, 'save_hardening' ) );
		add_action( 'wp_ajax_gsss_vuln_scan_step', array( $this, 'ajax_vuln_scan_step' ) );
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
		wp_localize_script(
			'gsss-admin',
			'gsssAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'gsss_admin' ),
				'i18n'    => array(
					'sending'    => __( 'Envoi en cours…', 'graphin-simple-security-ssl' ),
					'error'      => __( 'Erreur de communication avec le site.', 'graphin-simple-security-ssl' ),
					/* translators: 1: composants analysés, 2: total */
					'scanning'   => __( 'Analyse : %1$s / %2$s', 'graphin-simple-security-ssl' ),
					'copied'     => __( 'Copié.', 'graphin-simple-security-ssl' ),
					'copyFailed' => __( 'Copie impossible : sélectionnez le texte à la main.', 'graphin-simple-security-ssl' ),
					'scanDone'   => __( 'Analyse terminée.', 'graphin-simple-security-ssl' ),
				),
			)
		);
	}

	/**
	 * Enregistre les réglages généraux (admin-post, nonce, droits).
	 *
	 * @return void
	 */
	public function save_settings() {
		check_admin_referer( 'gsss_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Accès refusé.', 'graphin-simple-security-ssl' ), '', array( 'response' => 403 ) );
		}

		$agency = isset( $_POST['agency_email'] ) ? sanitize_email( wp_unslash( $_POST['agency_email'] ) ) : '';
		$client = isset( $_POST['client_email'] ) ? sanitize_email( wp_unslash( $_POST['client_email'] ) ) : '';
		$mode   = isset( $_POST['server_mode'] ) ? sanitize_key( wp_unslash( $_POST['server_mode'] ) ) : 'apache';
		$alert  = empty( $_POST['alert_client'] ) ? 0 : 1;

		$notice = 'saved';
		if ( ! is_email( $agency ) || ( $alert && ! is_email( $client ) ) ) {
			$notice = 'invalid_email';
		} else {
			$previous = Settings::get( 'server_mode' );
			Settings::set( 'server_mode', $mode );
			Settings::set( 'agency_email', $agency );
			Settings::set( 'alert_client', $alert );
			Settings::set( 'client_email', $client );
			Logger::log( 'settings_saved', __( 'Réglages généraux enregistrés.', 'graphin-simple-security-ssl' ) );
			if ( Settings::get( 'server_mode' ) !== $previous ) {
				$result = Htaccess::sync();
				if ( is_wp_error( $result ) ) {
					$notice = 'htaccess_error';
				}
			}
		}

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => 'gsss-settings',
					'gsss_notice' => $notice,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Enregistre les cases du module Durcissement, puis aligne les fichiers .htaccess.
	 *
	 * @return void
	 */
	public function save_hardening() {
		check_admin_referer( 'gsss_save_hardening' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Accès refusé.', 'graphin-simple-security-ssl' ), '', array( 'response' => 403 ) );
		}
		foreach ( array_keys( Hardening::options() ) as $key ) {
			Settings::set( $key, empty( $_POST[ $key ] ) ? 0 : 1 );
		}
		Logger::log( 'settings_saved', __( 'Réglages Durcissement enregistrés.', 'graphin-simple-security-ssl' ) );
		$notice = is_wp_error( Htaccess::sync() ) ? 'htaccess_error' : 'saved';
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => 'gsss-hardening',
					'gsss_notice' => $notice,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Enregistre les réglages du module Vulnérabilités.
	 *
	 * @return void
	 */
	public function save_vulns() {
		check_admin_referer( 'gsss_save_vulns' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Accès refusé.', 'graphin-simple-security-ssl' ), '', array( 'response' => 403 ) );
		}
		$severity = isset( $_POST['vuln_min_severity'] ) ? sanitize_key( wp_unslash( $_POST['vuln_min_severity'] ) ) : 'medium';
		if ( ! in_array( $severity, array( 'low', 'medium', 'high', 'critical' ), true ) ) {
			$severity = 'medium';
		}
		$enabled = empty( $_POST['vuln_enabled'] ) ? 0 : 1;
		Settings::set( 'vuln_enabled', $enabled );
		Settings::set( 'vuln_min_severity', $severity );
		Settings::set( 'vuln_auto_update', empty( $_POST['vuln_auto_update'] ) ? 0 : 1 );
		Settings::set( 'vuln_flag_closed', empty( $_POST['vuln_flag_closed'] ) ? 0 : 1 );
		Vulnerabilities::sync_schedule( (bool) $enabled );
		Logger::log( 'settings_saved', __( 'Réglages Vulnérabilités enregistrés.', 'graphin-simple-security-ssl' ) );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => 'gsss-vulns',
					'gsss_notice' => 'saved',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Traite un lot du scan (AJAX, nonce, droits). Le scan doit être activé.
	 *
	 * @return void
	 */
	public function ajax_vuln_scan_step() {
		check_ajax_referer( 'gsss_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Accès refusé.', 'graphin-simple-security-ssl' ) ), 403 );
		}
		if ( ! Settings::get( 'vuln_enabled' ) ) {
			wp_send_json_error( array( 'message' => __( 'Cochez d\'abord « Activer le scan » et enregistrez.', 'graphin-simple-security-ssl' ) ) );
		}
		if ( ! empty( $_POST['start'] ) ) {
			VulnScanner::reset();
		}
		wp_send_json_success( VulnScanner::step() );
	}

	/**
	 * Envoie l'email de test (AJAX, nonce, droits).
	 *
	 * @return void
	 */
	public function ajax_send_test_mail() {
		check_ajax_referer( 'gsss_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Accès refusé.', 'graphin-simple-security-ssl' ) ), 403 );
		}
		if ( Mailer::send_test() ) {
			/* translators: %s: adresses email */
			wp_send_json_success( array( 'message' => sprintf( __( 'Email envoyé à : %s', 'graphin-simple-security-ssl' ), implode( ', ', Mailer::recipients() ) ) ) );
		}
		wp_send_json_error( array( 'message' => __( 'L\'email n\'a pas pu être envoyé. Voir le journal.', 'graphin-simple-security-ssl' ) ) );
	}
}
