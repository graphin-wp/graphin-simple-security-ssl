<?php
/**
 * Module SSL : détection du certificat, passage en https, redirection, HSTS, contenu mixte.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Modules;

use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * La redirection et HSTS passent par .htaccess (Apache) quand les règles sont servies, sinon par PHP.
 */
class Ssl extends Module {

	const DETECT_OPTION = 'gsss_ssl_detect';
	const URLS_OPTION   = 'gsss_ssl_previous_urls';
	const HSTS_MAX_AGE  = 31536000;
	const REDIRECT_FLAG = 'gsss_ssl_redirect_php';
	const HSTS_FLAG     = 'gsss_hsts_via_php';

	/**
	 * Déclare les valeurs par défaut, même quand le module est inactif.
	 */
	public function __construct() {
		add_filter( 'gsss_default_settings', array( $this, 'defaults' ) );
	}

	/**
	 * Valeurs par défaut : rien n'agit tant que le SSL n'est pas activé.
	 *
	 * @param array $defaults Valeurs existantes.
	 * @return array
	 */
	public function defaults( $defaults ) {
		return array_merge(
			$defaults,
			array(
				'ssl_enabled'         => 0,
				'ssl_www'             => 'none',
				'ssl_mixed_front'     => 0,
				'ssl_mixed_admin'     => 0,
				'ssl_hsts'            => 0,
				'ssl_hsts_subdomains' => 0,
				'ssl_hsts_preload'    => 0,
			)
		);
	}

	/**
	 * Identifiant.
	 *
	 * @return string
	 */
	public function id() {
		return 'ssl';
	}

	/**
	 * Actif seulement après « Activer le SSL ».
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) Settings::get( 'ssl_enabled' );
	}

	/**
	 * Hôte du site, sans port.
	 *
	 * @return string
	 */
	public static function host() {
		return strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	}

	/**
	 * Hôte sans le préfixe www.
	 *
	 * @param string|null $host Hôte, celui du site par défaut.
	 * @return string
	 */
	public static function bare_host( $host = null ) {
		return preg_replace( '/^www\./', '', null === $host ? self::host() : $host );
	}

	/**
	 * L'adresse du site commence-t-elle par www ?
	 *
	 * @return bool
	 */
	public static function is_www() {
		return 0 === strpos( self::host(), 'www.' );
	}

	/**
	 * Adresse https testée par la détection.
	 *
	 * @return string
	 */
	public static function https_url() {
		/**
		 * Adresse https du site, pour un port HTTPS non standard.
		 *
		 * @param string $url Adresse.
		 */
		return (string) apply_filters( 'gsss_ssl_https_url', 'https://' . self::host() . '/' );
	}

	/**
	 * Hôte (et port s'il n'est pas standard) vers lequel la redirection envoie.
	 *
	 * @return string
	 */
	public static function target_authority() {
		$port = wp_parse_url( self::https_url(), PHP_URL_PORT );
		return self::host() . ( $port && 443 !== (int) $port ? ':' . (int) $port : '' );
	}

	/**
	 * Autre variante de l'hôte (avec ou sans www) redirigée vers l'hôte du site, ou chaîne vide.
	 *
	 * @return string
	 */
	public static function other_host() {
		$www = Settings::get( 'ssl_www' );
		if ( 'www' === $www && self::is_www() ) {
			return self::bare_host();
		}
		if ( 'non-www' === $www && ! self::is_www() ) {
			return 'www.' . self::host();
		}
		return '';
	}

	/**
	 * Le choix www est-il compatible avec l'adresse du site ? Forcer la variante opposée ferait boucler
	 * la redirection avec celle de WordPress.
	 *
	 * @param string $choice none, www ou non-www.
	 * @return bool
	 */
	public static function www_matches( $choice ) {
		return 'none' === $choice || ( 'www' === $choice && self::is_www() ) || ( 'non-www' === $choice && ! self::is_www() );
	}

	/**
	 * Valeur de l'en-tête HSTS. preload n'est accepté par les navigateurs qu'avec includeSubDomains.
	 *
	 * @return string
	 */
	public static function hsts_value() {
		$preload = (bool) Settings::get( 'ssl_hsts_preload' );
		$value   = 'max-age=' . self::HSTS_MAX_AGE;
		if ( $preload || Settings::get( 'ssl_hsts_subdomains' ) ) {
			$value .= '; includeSubDomains';
		}
		return $preload ? $value . '; preload' : $value;
	}

	/**
	 * Détecte un certificat valide sur l'adresse https et mémorise le résultat.
	 *
	 * @return array ok, message, expires (horodatage, 0 si inconnu), checked.
	 */
	public static function detect() {
		$url      = self::https_url();
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 10,
				'redirection' => 0,
				'sslverify'   => true,
				'user-agent'  => 'Graphin-Simple-Security/' . GSSS_VERSION,
			)
		);
		$result   = array(
			'ok'      => false,
			'message' => '',
			'expires' => self::certificate_expiry( $url ),
			'checked' => time(),
		);
		if ( is_wp_error( $response ) ) {
			$result['message'] = self::explain_error( $response->get_error_message() );
		} elseif ( (int) wp_remote_retrieve_response_code( $response ) >= 500 ) {
			/* translators: %d: code HTTP */
			$result['message'] = sprintf( __( 'Le certificat est valide, mais le site répond en https avec une erreur %d.', 'graphin-simple-security-ssl' ), (int) wp_remote_retrieve_response_code( $response ) );
		} else {
			$result['ok']      = true;
			$result['message'] = __( 'Un certificat valide répond en https.', 'graphin-simple-security-ssl' );
		}
		update_option( self::DETECT_OPTION, $result, false );
		return $result;
	}

	/**
	 * Dernière détection, ou null.
	 *
	 * @return array|null
	 */
	public static function last_detection() {
		$result = get_option( self::DETECT_OPTION );
		return is_array( $result ) ? $result : null;
	}

	/**
	 * Message lisible pour une erreur de transport.
	 *
	 * @param string $raw Message de cURL ou de PHP.
	 * @return string
	 */
	private static function explain_error( $raw ) {
		$raw = strtolower( $raw );
		if ( false !== strpos( $raw, 'certificate' ) || false !== strpos( $raw, 'ssl' ) ) {
			return __( 'Le certificat est absent, expiré, auto-signé ou ne couvre pas ce domaine. Installez un certificat (Let\'s Encrypt chez OVH) puis revérifiez.', 'graphin-simple-security-ssl' );
		}
		if ( false !== strpos( $raw, 'resolve' ) ) {
			return __( 'Le nom de domaine ne se résout pas depuis le serveur.', 'graphin-simple-security-ssl' );
		}
		if ( false !== strpos( $raw, 'timed out' ) || false !== strpos( $raw, 'connect' ) ) {
			return __( 'Le serveur ne répond pas sur le port https (443).', 'graphin-simple-security-ssl' );
		}
		/* translators: %s: message technique */
		return sprintf( __( 'La requête https a échoué : %s', 'graphin-simple-security-ssl' ), $raw );
	}

	/**
	 * Date d'expiration du certificat présenté, lue en local (aucun service tiers).
	 *
	 * @param string $url Adresse https.
	 * @return int Horodatage, 0 si illisible.
	 */
	private static function certificate_expiry( $url ) {
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		$port = (int) wp_parse_url( $url, PHP_URL_PORT );
		if ( '' === $host || ! function_exists( 'openssl_x509_parse' ) || ! function_exists( 'stream_socket_client' ) ) {
			return 0;
		}
		// Vérification désactivée ici seulement : la validité est jugée par detect(), on lit juste la date,
		// y compris celle d'un certificat expiré pour l'afficher.
		$context = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => false,
					'verify_peer_name'  => false,
					'peer_name'         => $host,
					'SNI_enabled'       => true,
				),
			)
		);
		$errno   = 0;
		$errstr  = '';
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Un échec de connexion est un cas normal, traité juste après.
		$socket = @stream_socket_client( 'ssl://' . $host . ':' . ( $port ? $port : 443 ), $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context );
		if ( ! $socket ) {
			return 0;
		}
		$params = stream_context_get_params( $socket );
		fclose( $socket ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		if ( empty( $params['options']['ssl']['peer_certificate'] ) ) {
			return 0;
		}
		$cert = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
		return isset( $cert['validTo_time_t'] ) ? (int) $cert['validTo_time_t'] : 0;
	}

	/**
	 * Adresses fixées dans wp-config.php en http : WordPress les impose, le passage en https est impossible.
	 *
	 * @return bool
	 */
	public static function constants_block() {
		$blocked = ( defined( 'WP_HOME' ) && 0 === stripos( (string) WP_HOME, 'http://' ) )
			|| ( defined( 'WP_SITEURL' ) && 0 === stripos( (string) WP_SITEURL, 'http://' ) );
		/**
		 * Contrôle des constantes WP_HOME et WP_SITEURL (forcé à faux par les tests, qui les fixent en http).
		 *
		 * @param bool $blocked Vrai si une constante impose http.
		 */
		return (bool) apply_filters( 'gsss_ssl_constants_block', $blocked );
	}

	/**
	 * Active le SSL : adresses en https, règles .htaccess, vérification de ce que sert Apache.
	 *
	 * @return true|\WP_Error Vrai, ou erreur (rien n'a changé).
	 */
	public static function enable() {
		if ( is_multisite() ) {
			return new \WP_Error( 'multisite', '' );
		}
		if ( self::constants_block() ) {
			return new \WP_Error( 'constants', '' );
		}
		$detection = self::detect();
		if ( ! $detection['ok'] ) {
			return new \WP_Error( 'detect', $detection['message'] );
		}

		$previous = array(
			'home'    => get_option( 'home' ),
			'siteurl' => get_option( 'siteurl' ),
		);
		$changed  = false;
		foreach ( $previous as $key => $url ) {
			if ( 0 === stripos( $url, 'http://' ) ) {
				update_option( $key, set_url_scheme( $url, 'https' ) );
				$changed = true;
			}
		}
		// Seules les adresses changées par le plugin repasseront en http avec « Revenir en HTTP ».
		update_option( self::URLS_OPTION, $changed ? $previous : array(), false );
		Settings::set( 'ssl_enabled', 1 );

		$sync = Htaccess::sync_or_restore(
			function () {
				self::restore_urls();
				Settings::set( 'ssl_enabled', 0 );
			}
		);
		if ( is_wp_error( $sync ) && 'gsss_htaccess_rollback' === $sync->get_error_code() ) {
			return new \WP_Error( 'rollback', $sync->get_error_message() );
		}
		self::verify_delivery();
		// Cookie de connexion sécurisé : l'administrateur reste connecté une fois en https.
		if ( ! is_ssl() && is_user_logged_in() ) {
			wp_set_auth_cookie( get_current_user_id(), false, true );
		}
		Logger::log( 'ssl_enabled', __( 'SSL activé.', 'graphin-simple-security-ssl' ), array( 'urls_changed' => $changed ), 'warning' );
		return true;
	}

	/**
	 * Revient en HTTP : retire redirection et HSTS, remet les adresses changées par le plugin.
	 *
	 * @return void
	 */
	public static function revert() {
		Settings::set( 'ssl_enabled', 0 );
		Settings::set( 'ssl_hsts', 0 );
		self::restore_urls();
		Htaccess::sync();
		self::verify_delivery();
		// Cookie non sécurisé si l'administration repasse en http, sinon la session serait perdue.
		if ( is_user_logged_in() && 0 === stripos( (string) get_option( 'siteurl' ), 'http://' ) ) {
			wp_set_auth_cookie( get_current_user_id(), false, false );
		}
		Logger::log( 'ssl_reverted', __( 'Retour en HTTP : redirection et HSTS retirés.', 'graphin-simple-security-ssl' ), array(), 'warning' );
	}

	/**
	 * Remet les adresses mémorisées à l'activation.
	 *
	 * @return void
	 */
	private static function restore_urls() {
		$previous = get_option( self::URLS_OPTION );
		if ( is_array( $previous ) && ! self::constants_block() ) {
			foreach ( array( 'home', 'siteurl' ) as $key ) {
				if ( ! empty( $previous[ $key ] ) ) {
					update_option( $key, $previous[ $key ] );
				}
			}
		}
		delete_option( self::URLS_OPTION );
	}

	/**
	 * La redirection passe-t-elle par PHP ?
	 *
	 * @return bool
	 */
	public static function redirect_via_php() {
		return Htaccess::served_by_php( self::REDIRECT_FLAG );
	}

	/**
	 * HSTS passe-t-il par PHP ?
	 *
	 * @return bool
	 */
	public static function hsts_via_php() {
		return Htaccess::served_by_php( self::HSTS_FLAG );
	}

	/**
	 * Vérifie que la redirection et HSTS écrits dans .htaccess sont réellement servis
	 * (mod_rewrite ou mod_headers peuvent manquer : le bloc <IfModule> est alors ignoré sans erreur).
	 * Ce qui ne revient pas passe par PHP.
	 *
	 * @return array redirect, hsts : vrai si servi par Apache.
	 */
	public static function verify_delivery() {
		$result = array(
			'redirect' => false,
			'hsts'     => false,
		);
		if ( ! Settings::get( 'ssl_enabled' ) || ! Htaccess::rules_served() ) {
			delete_option( self::REDIRECT_FLAG );
			delete_option( self::HSTS_FLAG );
			return $result;
		}
		// PHP se tait le temps du test, pour ne voir que ce que sert Apache.
		update_option( self::REDIRECT_FLAG, 0, true );
		update_option( self::HSTS_FLAG, 0, true );
		$args = array(
			'timeout'     => 10,
			'redirection' => 0,
			'user-agent'  => 'Graphin-Simple-Security/' . GSSS_VERSION,
		);

		$check              = add_query_arg( 'gsss_ssl_check', (string) time(), '/' );
		$response           = wp_remote_get( set_url_scheme( home_url( $check ), 'http' ), $args );
		$location           = is_wp_error( $response ) ? '' : (string) wp_remote_retrieve_header( $response, 'location' );
		$result['redirect'] = ! is_wp_error( $response ) && 301 === (int) wp_remote_retrieve_response_code( $response ) && 0 === stripos( $location, 'https://' );
		update_option( self::REDIRECT_FLAG, $result['redirect'] ? 0 : 1, true );

		if ( Settings::get( 'ssl_hsts' ) ) {
			$response       = wp_remote_get( set_url_scheme( home_url( $check ), 'https' ), $args );
			$result['hsts'] = ! is_wp_error( $response ) && '' !== (string) wp_remote_retrieve_header( $response, 'strict-transport-security' );
			update_option( self::HSTS_FLAG, $result['hsts'] ? 0 : 1, true );
		} else {
			delete_option( self::HSTS_FLAG );
		}
		return $result;
	}

	/**
	 * Hooks du module.
	 *
	 * @return void
	 */
	public function register_hooks() {
		// Derrière un proxy qui termine le https, WordPress croit être en http et renverrait vers https
		// sans fin. Le proxy le signale par X-Forwarded-Proto.
		// HTTPS peut valoir « off » plutôt qu'être absent : is_ssl() couvre les deux cas.
		if ( ! is_ssl() && isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 'https' === strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) ) ) {
			$_SERVER['HTTPS'] = 'on';
		}
		add_action( 'template_redirect', array( $this, 'redirect' ), 1 );
		add_action( 'login_init', array( $this, 'redirect' ), 1 );
		add_action( 'admin_init', array( $this, 'redirect' ), 1 );
		add_action( 'send_headers', array( $this, 'send_hsts' ) );
		if ( Settings::get( 'ssl_mixed_front' ) ) {
			add_action( 'template_redirect', array( $this, 'start_buffer' ), 0 );
		}
		if ( Settings::get( 'ssl_mixed_admin' ) ) {
			add_action( 'admin_init', array( $this, 'start_buffer' ), 0 );
		}
	}

	/**
	 * Redirection 301 vers https (et vers la bonne variante www) quand Apache ne s'en charge pas.
	 * GET et HEAD seulement : un formulaire envoyé en http ne perd pas ses données.
	 *
	 * @return void
	 */
	public function redirect() {
		if ( ! self::redirect_via_php() || wp_doing_ajax() || wp_doing_cron() || ! isset( $_SERVER['REQUEST_METHOD'], $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ) {
			return;
		}
		$method = strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) );
		if ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) ) {
			return;
		}
		$host  = strtolower( preg_replace( '/:\d+$/', '', sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) ) );
		$other = self::other_host();
		if ( self::bare_host() !== self::bare_host( $host ) ) {
			return;
		}
		if ( is_ssl() && ( '' === $other || $host !== $other ) ) {
			return;
		}
		// L'adresse demandée est passée telle quelle : wp_redirect la nettoie.
		$uri = wp_unslash( $_SERVER['REQUEST_URI'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		wp_redirect( 'https://' . self::target_authority() . $uri, 301, 'Graphin Simple Security' ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- La variante www n'est pas dans les hôtes autorisés.
		exit;
	}

	/**
	 * En-tête HSTS par PHP, en https seulement.
	 *
	 * @return void
	 */
	public function send_hsts() {
		if ( Settings::get( 'ssl_hsts' ) && is_ssl() && self::hsts_via_php() && ! headers_sent() ) {
			header( 'Strict-Transport-Security: ' . self::hsts_value() );
		}
	}

	/**
	 * Démarre le correcteur de contenu mixte.
	 *
	 * @return void
	 */
	public function start_buffer() {
		if ( is_ssl() && ! wp_doing_ajax() ) {
			ob_start( array( __CLASS__, 'fix_mixed_content' ) );
		}
	}

	/**
	 * Remplace http://domaine par https://domaine dans une page HTML. Les autres domaines ne bougent pas.
	 * Couvre src, href, srcset, url() CSS et le JSON échappé (http:\/\/domaine).
	 *
	 * @param string $html Contenu de la page.
	 * @return string
	 */
	public static function fix_mixed_content( $html ) {
		if ( ! is_string( $html ) || false === strpos( $html, '<' ) ) {
			return $html;
		}
		foreach ( headers_list() as $header ) {
			if ( 0 === stripos( $header, 'content-type:' ) && false === stripos( $header, 'html' ) ) {
				return $html;
			}
		}
		$pattern = '#http(://|:\\\\/\\\\/)((?:www\.)?' . preg_quote( self::bare_host(), '#' ) . ')(?![\w.-])#i';
		$fixed   = preg_replace( $pattern, 'https$1$2', $html );
		return null === $fixed ? $html : $fixed;
	}

	/**
	 * Règles Apache : redirection en un seul saut et HSTS.
	 *
	 * @return string[]
	 */
	public function htaccess_rules() {
		// Une règle par cas : http (toutes variantes), puis l'autre variante en https.
		$rules = array(
			array( '%{HTTPS} !=on', '%{HTTP:X-Forwarded-Proto} !=https', '%{HTTP_HOST} ^(www\.)?' . preg_quote( self::bare_host(), '' ) . '(:[0-9]+)?$ [NC]' ),
		);
		$other = self::other_host();
		if ( '' !== $other ) {
			$rules[] = array( '%{HTTP_HOST} ^' . preg_quote( $other, '' ) . '(:[0-9]+)?$ [NC]' );
		}
		$lines = array( '<IfModule mod_rewrite.c>', "\tRewriteEngine On" );
		foreach ( $rules as $conditions ) {
			array_unshift( $conditions, '%{REQUEST_METHOD} ^(GET|HEAD)$' );
			foreach ( $conditions as $condition ) {
				$lines[] = "\tRewriteCond " . $condition;
			}
			$lines[] = "\tRewriteRule ^ https://" . self::target_authority() . '%{REQUEST_URI} [R=301,L]';
		}
		$lines[] = '</IfModule>';
		if ( Settings::get( 'ssl_hsts' ) ) {
			$lines[] = '<IfModule mod_headers.c>';
			$lines[] = "\tHeader always set Strict-Transport-Security \"" . self::hsts_value() . "\" \"expr=%{HTTPS} == 'on' || %{HTTP:X-Forwarded-Proto} == 'https'\"";
			$lines[] = '</IfModule>';
		}
		return $lines;
	}

	/**
	 * Snippet Nginx équivalent.
	 *
	 * @return string
	 */
	public function nginx_rules() {
		$bare  = self::bare_host();
		$lines = array(
			'server {',
			"\tlisten 80;",
			"\tserver_name " . $bare . ' www.' . $bare . ';',
			"\treturn 301 https://" . self::target_authority() . '$request_uri;',
			'}',
		);
		if ( Settings::get( 'ssl_hsts' ) ) {
			$lines[] = '# Dans le bloc server en https :';
			$lines[] = 'add_header Strict-Transport-Security "' . self::hsts_value() . '" always;';
		}
		return implode( "\n", $lines );
	}
}
