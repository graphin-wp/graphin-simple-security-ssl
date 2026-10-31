<?php
/**
 * Menus et pages d'administration.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Admin;

use Graphin\SimpleSecurity\Crypto;
use Graphin\SimpleSecurity\CspReports;
use Graphin\SimpleSecurity\Dashboard;
use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Login\LoginLimiter;
use Graphin\SimpleSecurity\Login\LoginUrl;
use Graphin\SimpleSecurity\Login\Twofactor;
use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Mailer;
use Graphin\SimpleSecurity\Modules\Hardening;
use Graphin\SimpleSecurity\Modules\Headers;
use Graphin\SimpleSecurity\Modules\Ssl;
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
		add_action( 'admin_post_gsss_save_login', array( $this, 'save_login' ) );
		add_action( 'admin_post_gsss_save_headers', array( $this, 'save_headers' ) );
		add_action( 'admin_post_gsss_csp_allow', array( $this, 'csp_allow' ) );
		add_action( 'admin_post_gsss_csp_clear', array( $this, 'csp_clear' ) );
		add_action( 'admin_post_gsss_csp_mode', array( $this, 'csp_mode' ) );
		add_action( 'wp_ajax_gsss_test_headers', array( $this, 'ajax_test_headers' ) );
		add_action( 'wp_ajax_gsss_vuln_scan_step', array( $this, 'ajax_vuln_scan_step' ) );
		add_action( 'admin_post_gsss_ssl_save', array( $this, 'ssl_save' ) );
		add_action( 'admin_post_gsss_ssl_enable', array( $this, 'ssl_enable' ) );
		add_action( 'admin_post_gsss_ssl_revert', array( $this, 'ssl_revert' ) );
		add_action( 'wp_ajax_gsss_ssl_detect', array( $this, 'ajax_ssl_detect' ) );
		add_action( 'admin_post_gsss_apply_recommended', array( $this, 'apply_recommended' ) );
		add_action( 'admin_post_gsss_take_over_hardening', array( $this, 'take_over_hardening' ) );
		add_action( 'admin_post_gsss_export', array( $this, 'export_settings' ) );
		add_action( 'admin_post_gsss_import', array( $this, 'import_settings' ) );
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
					'present'    => __( 'Présent', 'graphin-simple-security-ssl' ),
					'absent'     => __( 'Absent', 'graphin-simple-security-ssl' ),
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
	 * Droits communs aux actions admin-post (le nonce est vérifié par chaque action).
	 *
	 * @return void
	 */
	private function guard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Accès refusé.', 'graphin-simple-security-ssl' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Retour vers une page du plugin avec un message.
	 *
	 * @param string $page   Slug de la page.
	 * @param string $notice Code du message.
	 * @return void
	 */
	private function back( $page, $notice ) {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => $page,
					'gsss_notice' => $notice,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Enregistre les cases du module En-têtes, puis aligne .htaccess.
	 *
	 * @return void
	 */
	public function save_headers() {
		check_admin_referer( 'gsss_save_headers' );
		$this->guard();
		foreach ( array( 'hdr_nosniff', 'hdr_xfo', 'hdr_referrer', 'hdr_permissions', 'hdr_coop', 'hdr_xss', 'hdr_csp', 'hdr_csp_upgrade' ) as $key ) {
			Settings::set( $key, empty( $_POST[ $key ] ) ? 0 : 1 );
		}
		$referrer = isset( $_POST['hdr_referrer_value'] ) ? sanitize_text_field( wp_unslash( $_POST['hdr_referrer_value'] ) ) : '';
		Settings::set( 'hdr_referrer_value', in_array( $referrer, Headers::referrer_values(), true ) ? $referrer : 'strict-origin-when-cross-origin' );
		$features = isset( $_POST['hdr_perm_features'] ) && is_array( $_POST['hdr_perm_features'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['hdr_perm_features'] ) ) : array();
		Settings::set( 'hdr_perm_features', array_values( array_intersect( Headers::features(), $features ) ) );
		Logger::log( 'settings_saved', __( 'Réglages En-têtes enregistrés.', 'graphin-simple-security-ssl' ) );
		if ( is_wp_error( Htaccess::sync() ) ) {
			$this->back( 'gsss-headers', 'htaccess_error' );
		}
		$via_apache = Headers::verify_delivery();
		$this->back( 'gsss-headers', ( ! $via_apache && 'apache' === Settings::get( 'server_mode' ) && ! empty( Headers::simple_headers() ) ) ? 'headers_php' : 'saved' );
	}

	/**
	 * Autorise la source d'un rapport CSP.
	 *
	 * @return void
	 */
	public function csp_allow() {
		check_admin_referer( 'gsss_csp_allow' );
		$this->guard();
		$id     = isset( $_POST['report'] ) ? preg_replace( '/[^a-f0-9]/', '', sanitize_text_field( wp_unslash( $_POST['report'] ) ) ) : '';
		$result = CspReports::allow( $id );
		if ( true === $result ) {
			Logger::log( 'csp_allowed', __( 'Source ajoutée à la politique CSP.', 'graphin-simple-security-ssl' ), array( 'report' => $id ), 'warning' );
		}
		$this->back( 'gsss-headers', true === $result ? 'csp_allowed' : 'csp_' . $result );
	}

	/**
	 * Vide la liste des rapports CSP.
	 *
	 * @return void
	 */
	public function csp_clear() {
		check_admin_referer( 'gsss_csp_clear' );
		$this->guard();
		CspReports::clear();
		$this->back( 'gsss-headers', 'csp_cleared' );
	}

	/**
	 * Bascule la CSP entre rapport seulement et appliquée. L'application exige une liste de rapports vide.
	 *
	 * @return void
	 */
	public function csp_mode() {
		check_admin_referer( 'gsss_csp_mode' );
		$this->guard();
		$mode = isset( $_POST['mode'] ) && 'enforce' === $_POST['mode'] ? 'enforce' : 'report';
		if ( 'enforce' === $mode && ! empty( CspReports::all() ) ) {
			$this->back( 'gsss-headers', 'csp_pending' );
		}
		Settings::set( 'hdr_csp_mode', $mode );
		Logger::log( 'csp_mode', 'enforce' === $mode ? __( 'CSP appliquée.', 'graphin-simple-security-ssl' ) : __( 'CSP en rapport seulement.', 'graphin-simple-security-ssl' ), array(), 'warning' );
		$this->back( 'gsss-headers', 'csp_mode_' . $mode );
	}

	/**
	 * Demande la page d'accueil et renvoie les en-têtes reçus (AJAX).
	 *
	 * @return void
	 */
	public function ajax_test_headers() {
		check_ajax_referer( 'gsss_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Accès refusé.', 'graphin-simple-security-ssl' ) ), 403 );
		}
		$response = wp_remote_get(
			add_query_arg( 'gsss_hdr_test', (string) time(), home_url( '/' ) ),
			array(
				'timeout'     => 10,
				'redirection' => 3,
				'user-agent'  => 'Graphin-Simple-Security/' . GSSS_VERSION,
			)
		);
		if ( is_wp_error( $response ) ) {
			wp_send_json_error( array( 'message' => __( 'Le site n\'a pas pu se joindre lui-même.', 'graphin-simple-security-ssl' ) ) );
		}
		$received = wp_remote_retrieve_headers( $response );
		$rows     = array();
		foreach ( array( 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Opener-Policy', 'X-XSS-Protection', 'Content-Security-Policy', 'Content-Security-Policy-Report-Only', 'Strict-Transport-Security' ) as $name ) {
			$value  = isset( $received[ $name ] ) ? $received[ $name ] : null;
			$rows[] = array(
				'name'  => $name,
				'value' => is_array( $value ) ? implode( ' | ', $value ) : $value,
			);
		}
		wp_send_json_success(
			array(
				'status' => (int) wp_remote_retrieve_response_code( $response ),
				'rows'   => $rows,
			)
		);
	}

	/**
	 * Enregistre les options du module SSL. Si le SSL est actif, les règles suivent ; si elles cassent le site,
	 * les options précédentes reviennent.
	 *
	 * @return void
	 */
	public function ssl_save() {
		check_admin_referer( 'gsss_ssl_save' );
		$this->guard();
		$keys     = array( 'ssl_www', 'ssl_mixed_front', 'ssl_mixed_admin', 'ssl_hsts', 'ssl_hsts_subdomains', 'ssl_hsts_preload' );
		$previous = array_intersect_key( Settings::all(), array_flip( $keys ) );
		$www      = isset( $_POST['ssl_www'] ) ? sanitize_key( wp_unslash( $_POST['ssl_www'] ) ) : 'none';
		if ( ! in_array( $www, Ssl::WWW_CHOICES, true ) ) {
			$www = 'none';
		}
		if ( ! Ssl::www_matches( $www ) ) {
			$this->back( 'gsss-ssl', 'www_mismatch' );
		}
		Settings::set( 'ssl_www', $www );
		foreach ( array_slice( $keys, 1 ) as $key ) {
			Settings::set( $key, empty( $_POST[ $key ] ) ? 0 : 1 );
		}
		Logger::log( 'settings_saved', __( 'Réglages SSL enregistrés.', 'graphin-simple-security-ssl' ) );
		if ( ! Settings::get( 'ssl_enabled' ) ) {
			$this->back( 'gsss-ssl', 'saved' );
		}
		$sync = Htaccess::sync_or_restore(
			function () use ( $previous ) {
				foreach ( $previous as $key => $value ) {
					Settings::set( $key, $value );
				}
			}
		);
		if ( is_wp_error( $sync ) && 'gsss_htaccess_rollback' === $sync->get_error_code() ) {
			$this->back( 'gsss-ssl', 'ssl_rollback' );
		}
		Ssl::verify_delivery();
		$this->back( 'gsss-ssl', is_wp_error( $sync ) ? 'htaccess_error' : 'saved' );
	}

	/**
	 * Active le SSL. Un cookie de connexion sécurisé est posé pour rester connecté une fois en https.
	 *
	 * @return void
	 */
	public function ssl_enable() {
		check_admin_referer( 'gsss_ssl_enable' );
		$this->guard();
		$result = Ssl::enable();
		$this->back( 'gsss-ssl', is_wp_error( $result ) ? 'ssl_' . $result->get_error_code() : 'ssl_enabled' );
	}

	/**
	 * Revient en HTTP. Un cookie de connexion non sécurisé est posé pour rester connecté en http.
	 *
	 * @return void
	 */
	public function ssl_revert() {
		check_admin_referer( 'gsss_ssl_revert' );
		$this->guard();
		Ssl::revert();
		$this->back( 'gsss-ssl', 'ssl_reverted' );
	}

	/**
	 * Relance la détection du certificat (AJAX).
	 *
	 * @return void
	 */
	public function ajax_ssl_detect() {
		check_ajax_referer( 'gsss_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Accès refusé.', 'graphin-simple-security-ssl' ) ), 403 );
		}
		wp_send_json_success( Ssl::detect() );
	}

	/**
	 * Code de message pour le résultat d'une action du tableau de bord.
	 *
	 * @param mixed  $result Résultat (WP_Error en cas d'échec).
	 * @param string $ok     Code en cas de succès.
	 * @param string $failed Code pour une autre erreur que la restauration.
	 * @return string
	 */
	private function notice_for( $result, $ok, $failed ) {
		if ( ! is_wp_error( $result ) ) {
			return $ok;
		}
		return Htaccess::is_rollback( $result ) ? 'rollback' : $failed;
	}

	/**
	 * Coche tous les réglages recommandés.
	 *
	 * @return void
	 */
	public function apply_recommended() {
		check_admin_referer( 'gsss_apply_recommended' );
		$this->guard();
		$this->back( 'gsss', $this->notice_for( Dashboard::apply_recommended(), 'recommended', 'htaccess_error' ) );
	}

	/**
	 * Reprend Graph'in Hardening puis le désactive.
	 *
	 * @return void
	 */
	public function take_over_hardening() {
		check_admin_referer( 'gsss_take_over_hardening' );
		$this->guard();
		$result = Dashboard::take_over_hardening();
		$this->back( 'gsss', is_wp_error( $result ) ? $this->notice_for( $result, '', 'hardening_absent' ) : 'hardening_done' . $result );
	}

	/**
	 * Télécharge les réglages en JSON.
	 *
	 * @return void
	 */
	public function export_settings() {
		check_admin_referer( 'gsss_export' );
		$this->guard();
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="gsss-' . sanitize_file_name( $host ) . '-' . gmdate( 'Y-m-d' ) . '.json"' );
		echo wp_json_encode( Dashboard::export(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		exit;
	}

	/**
	 * Importe un fichier de réglages (64 Ko au plus).
	 *
	 * @return void
	 */
	public function import_settings() {
		check_admin_referer( 'gsss_import' );
		$this->guard();
		$file = isset( $_FILES['gsss_file'] ) && is_array( $_FILES['gsss_file'] ) ? $_FILES['gsss_file'] : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Seul le chemin temporaire est lu, après is_uploaded_file().
		$tmp  = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';
		if ( '' === $tmp || ! is_uploaded_file( $tmp ) || (int) $file['size'] > 65536 ) {
			$this->back( 'gsss', 'import_invalid' );
		}
		$result = Dashboard::import( (string) file_get_contents( $tmp ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Fichier local envoyé par le formulaire.
		$this->back( 'gsss', $this->notice_for( $result, 'imported', 'import_invalid' ) );
	}

	/**
	 * Enregistre les réglages de connexion (double authentification).
	 *
	 * @return void
	 */
	public function save_login() {
		check_admin_referer( 'gsss_save_login' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Accès refusé.', 'graphin-simple-security-ssl' ), '', array( 'response' => 403 ) );
		}
		$enabled      = ! empty( $_POST['login_2fa_enabled'] ) && Crypto::available() ? 1 : 0;
		$enforce      = empty( $_POST['login_2fa_enforce'] ) ? 0 : 1;
		$grace        = isset( $_POST['login_2fa_grace'] ) ? absint( $_POST['login_2fa_grace'] ) : 7;
		$was_enforced = (bool) Settings::get( 'login_2fa_enforce' );
		Settings::set( 'login_2fa_enabled', $enabled );
		Settings::set( 'login_2fa_enforce', $enforce );
		Twofactor::sync_enforce_since( $was_enforced );
		Settings::set( 'login_2fa_grace', $grace );
		Settings::set( 'login_2fa_remember', empty( $_POST['login_2fa_remember'] ) ? 0 : 1 );

		// Limitation des tentatives.
		$was_limiting = (bool) Settings::get( 'login_limit_enabled' );
		$limiting     = empty( $_POST['login_limit_enabled'] ) ? 0 : 1;
		$whitelist    = array();
		$raw_list     = isset( $_POST['login_whitelist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['login_whitelist'] ) ) : '';
		foreach ( preg_split( '/\R/', $raw_list ) as $line ) {
			$ip = LoginLimiter::normalize_ip( $line );
			if ( '' !== $ip ) {
				$whitelist[] = $ip;
			}
		}
		// À l'activation, l'IP de l'administrateur est ajoutée à la liste blanche pour ne pas l'enfermer dehors.
		if ( $limiting && ! $was_limiting ) {
			$whitelist = LoginLimiter::with_own_ip( $whitelist );
		}
		Settings::set( 'login_limit_enabled', $limiting );
		Settings::set( 'login_limit_attempts', isset( $_POST['login_limit_attempts'] ) ? absint( $_POST['login_limit_attempts'] ) : 5 );
		Settings::set( 'login_limit_window', isset( $_POST['login_limit_window'] ) ? absint( $_POST['login_limit_window'] ) : 15 );
		Settings::set( 'login_limit_block', isset( $_POST['login_limit_block'] ) ? absint( $_POST['login_limit_block'] ) : 30 );
		Settings::set( 'login_proxy', empty( $_POST['login_proxy'] ) ? 0 : 1 );
		Settings::set( 'login_whitelist', array_values( array_unique( $whitelist ) ) );
		LoginLimiter::sync_schedule( (bool) $limiting );

		// URL de connexion personnalisée.
		$notice   = 'saved';
		$url_on   = empty( $_POST['login_url_enabled'] ) ? 0 : 1;
		$slug     = isset( $_POST['login_url_slug'] ) ? sanitize_title( wp_unslash( $_POST['login_url_slug'] ) ) : '';
		$previous = LoginUrl::slug();
		if ( $url_on ) {
			// Un slug déjà actif n'est pas re-testé contre le contenu du site (il l'a été à son activation).
			$check = ( '' !== $previous && $slug === $previous ) ? true : LoginUrl::validate_slug( $slug );
			if ( true !== $check ) {
				$notice = 'slug_' . $check;
				$url_on = 0;
				$slug   = $previous;
			}
		}
		Settings::set( 'login_url_enabled', $url_on );
		Settings::set( 'login_url_slug', $slug );
		if ( $url_on && $slug !== $previous ) {
			$notice = LoginUrl::notify( $slug ) ? 'url_active' : 'url_active_nomail';
			Logger::log( 'login_url_enabled', __( 'URL de connexion personnalisée activée.', 'graphin-simple-security-ssl' ), array( 'slug' => $slug ), 'warning' );
		} elseif ( ! $url_on && '' !== $previous && 'saved' === $notice ) {
			Logger::log( 'login_url_disabled', __( 'URL de connexion personnalisée désactivée.', 'graphin-simple-security-ssl' ) );
		}
		Logger::log( 'settings_saved', __( 'Réglages Connexion enregistrés.', 'graphin-simple-security-ssl' ) );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => 'gsss-login',
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
		if ( ! in_array( $severity, VulnScanner::SEVERITIES, true ) ) {
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
