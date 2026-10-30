<?php
/**
 * URL de connexion personnalisée.
 *
 * Le slug sert la page de connexion. wp-login.php et /wp-admin répondent 404 aux visiteurs
 * non connectés. Aucune règle serveur : tout passe par PHP, donc rien à nettoyer en cas de
 * désactivation, et GSSS_SAFE_MODE ou le renommage du dossier du plugin rétablissent tout.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Login;

use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Page de connexion à une adresse choisie.
 */
class LoginUrl {

	/**
	 * Mots interdits comme slug (adresses de WordPress et bases de réécriture).
	 *
	 * @var string[]
	 */
	private static $reserved = array(
		'wp-admin',
		'wp-login',
		'wp-content',
		'wp-includes',
		'wp-json',
		'wp-login-php',
		'admin',
		'login',
		'dashboard',
		'feed',
		'xmlrpc',
		'index',
		'author',
		'category',
		'tag',
		'page',
		'search',
		'comments',
		'embed',
		'sitemap',
	);

	/**
	 * Fichiers de /wp-admin que les visiteurs non connectés peuvent atteindre.
	 *
	 * @var string[]
	 */
	private static $open_admin_files = array( 'admin-ajax.php', 'admin-post.php', 'load-styles.php', 'load-scripts.php', 'upgrade.php', 'install.php', 'repair.php' );

	/**
	 * Slug actif, ou chaîne vide si le bloc est coupé ou le slug invalide.
	 *
	 * @return string
	 */
	public static function slug() {
		$slug = (string) Settings::get( 'login_url_slug', '' );
		if ( ! Settings::get( 'login_url_enabled' ) || true !== self::validate_slug( $slug, false ) ) {
			return '';
		}
		return $slug;
	}

	/**
	 * Adresse complète de la page de connexion personnalisée.
	 *
	 * @param string $slug Slug.
	 * @return string
	 */
	public static function url( $slug ) {
		return home_url( '/' . $slug );
	}

	/**
	 * Vérifie un slug.
	 *
	 * @param string $slug      Slug.
	 * @param bool   $check_use Vérifier aussi qu'il n'est pas déjà pris par un contenu du site.
	 * @return true|string Vrai, ou le code de l'erreur : multisite, format, reserved, taken.
	 */
	public static function validate_slug( $slug, $check_use = true ) {
		if ( is_multisite() ) {
			return 'multisite';
		}
		if ( ! preg_match( '/^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/', $slug ) ) {
			return 'format';
		}
		if ( in_array( $slug, self::$reserved, true ) ) {
			return 'reserved';
		}
		if ( $check_use && ( get_page_by_path( $slug, OBJECT, get_post_types( array( 'public' => true ) ) ) || term_exists( $slug ) ) ) {
			return 'taken';
		}
		return true;
	}

	/**
	 * Prévient l'agence et l'administrateur de la nouvelle adresse.
	 *
	 * @param string $slug Slug activé.
	 * @return bool
	 */
	public static function notify( $slug ) {
		$to = array();
		foreach ( array( Settings::get( 'agency_email' ), get_option( 'admin_email' ) ) as $address ) {
			if ( is_email( $address ) ) {
				$to[] = $address;
			}
		}
		$to   = array_values( array_unique( $to ) );
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$sent = ! empty( $to ) && wp_mail(
			$to,
			/* translators: %s: nom du site */
			sprintf( __( '[%s] Nouvelle adresse de connexion', 'graphin-simple-security-ssl' ), $site ),
			/* translators: %s: adresse de connexion */
			sprintf( __( "La page de connexion du site est maintenant :\n%s\n\nL'ancienne adresse (wp-login.php) et /wp-admin répondent 404 aux visiteurs non connectés. Conservez ce message.\n\nEn cas de blocage : ajoutez define( 'GSSS_SAFE_MODE', true ); dans wp-config.php, ou renommez le dossier du plugin graphin-simple-security-ssl en FTP. L'adresse habituelle fonctionne alors de nouveau.", 'graphin-simple-security-ssl' ), self::url( $slug ) )
		);
		Logger::log( $sent ? 'login_url_mailed' : 'login_url_mail_failed', __( 'Nouvelle adresse de connexion communiquée par email.', 'graphin-simple-security-ssl' ), array( 'to' => $to ), $sent ? 'info' : 'error' );
		return (bool) $sent;
	}

	/**
	 * Branche les hooks si un slug valide est actif.
	 *
	 * @return void
	 */
	public function register_hooks() {
		if ( '' === self::slug() ) {
			return;
		}
		add_action( 'init', array( $this, 'guard' ), 1 );
		add_action( 'wp_loaded', array( $this, 'serve_login' ), 0 );
		add_filter( 'site_url', array( $this, 'rewrite_url' ), 100 );
		add_filter( 'network_site_url', array( $this, 'rewrite_url' ), 100 );
		add_filter( 'wp_redirect', array( $this, 'rewrite_url' ), 100 );
		// /login et /admin redirigeraient les visiteurs vers l'adresse personnalisée : on les neutralise.
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/**
	 * Chemin de la requête, sans le dossier d'installation ni les barres, en minuscules.
	 *
	 * @return string
	 */
	private static function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Seul le chemin est extrait et comparé.
		$path = trim( (string) wp_parse_url( $uri, PHP_URL_PATH ), '/' );
		$base = trim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
		if ( '' !== $base && 0 === strpos( $path, $base ) ) {
			$path = trim( substr( $path, strlen( $base ) ), '/' );
		}
		return strtolower( rawurldecode( $path ) );
	}

	/**
	 * Réponse 404 neutre, qui ne cite pas WordPress.
	 *
	 * @return void
	 */
	private function deny() {
		status_header( 404 );
		nocache_headers();
		wp_die( esc_html__( 'Page introuvable.', 'graphin-simple-security-ssl' ), esc_html__( 'Page introuvable', 'graphin-simple-security-ssl' ), array( 'response' => 404 ) );
	}

	/**
	 * Ferme wp-login.php et /wp-admin aux visiteurs non connectés.
	 *
	 * @return void
	 */
	public function guard() {
		if ( is_user_logged_in() ) {
			return;
		}
		$path = self::request_path();
		$file = basename( $path );

		if ( 'wp-login.php' === $file ) {
			$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Lecture seule.
			if ( 'postpass' === $action ) {
				return; // Articles protégés par mot de passe.
			}
			$this->deny();
		}
		if ( 'wp-admin' === $path || 0 === strpos( $path, 'wp-admin/' ) ) {
			if ( in_array( $file, self::$open_admin_files, true ) ) {
				return;
			}
			$this->deny();
		}
	}

	/**
	 * Sert la page de connexion à l'adresse choisie.
	 *
	 * @return void
	 */
	public function serve_login() {
		if ( self::request_path() !== self::slug() ) {
			return;
		}
		global $pagenow;
		$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Contexte de la page de connexion.
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Remplace wp-login.php par le slug dans une adresse.
	 *
	 * @param string $url Adresse.
	 * @return string
	 */
	public function rewrite_url( $url ) {
		if ( is_string( $url ) && false !== strpos( $url, 'wp-login.php' ) ) {
			return preg_replace( '~(?<=/)wp-login\.php~', self::slug(), $url );
		}
		return $url;
	}
}
