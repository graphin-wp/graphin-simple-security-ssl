<?php
/**
 * Module En-têtes de sécurité : en-têtes HTTP et Content-Security-Policy.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Modules;

use Graphin\SimpleSecurity\CspReports;
use Graphin\SimpleSecurity\Htaccess;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * En-têtes envoyés par .htaccess (Apache) ou par PHP. La CSP passe toujours par PHP, sur le site public.
 */
class Headers extends Module {

	const POLICY_OPTION = 'gsss_csp_policy';

	/**
	 * Fonctionnalités de Permissions-Policy proposées.
	 *
	 * @return string[]
	 */
	public static function features() {
		return array( 'camera', 'microphone', 'geolocation', 'payment', 'usb', 'accelerometer', 'gyroscope', 'magnetometer', 'midi', 'display-capture' );
	}

	/**
	 * Valeurs de Referrer-Policy proposées.
	 *
	 * @return string[]
	 */
	public static function referrer_values() {
		return array( 'strict-origin-when-cross-origin', 'no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin', 'strict-origin', 'origin-when-cross-origin', 'unsafe-url' );
	}

	/**
	 * Politique de départ, compatible WordPress et Enfold.
	 *
	 * @return array
	 */
	public static function default_policy() {
		return array(
			'default-src' => array( "'self'" ),
			'script-src'  => array( "'self'", "'unsafe-inline'" ),
			'style-src'   => array( "'self'", "'unsafe-inline'" ),
			'img-src'     => array( "'self'", 'data:' ),
			'font-src'    => array( "'self'", 'data:' ),
		);
	}

	/**
	 * Description des cases simples : clé => libellé, aide, recommandée, avertissement.
	 *
	 * @return array
	 */
	public static function options() {
		return array(
			'hdr_nosniff'     => array(
				'label'       => __( 'X-Content-Type-Options : nosniff', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Le navigateur ne devine plus le type d\'un fichier : un fichier mal étiqueté n\'est pas exécuté comme un script.', 'graphin-simple-security-ssl' ),
				'recommended' => true,
				'warning'     => '',
			),
			'hdr_xfo'         => array(
				'label'       => __( 'X-Frame-Options : SAMEORIGIN', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Le site ne peut être affiché dans un cadre que par lui-même : protège contre le détournement de clic.', 'graphin-simple-security-ssl' ),
				'recommended' => true,
				'warning'     => __( 'Casse l\'intégration du site dans une page d\'un autre domaine.', 'graphin-simple-security-ssl' ),
			),
			'hdr_referrer'    => array(
				'label'       => __( 'Referrer-Policy', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Limite ce que le site révèle de l\'adresse de la page d\'origine quand un visiteur suit un lien.', 'graphin-simple-security-ssl' ),
				'recommended' => true,
				'warning'     => '',
			),
			'hdr_permissions' => array(
				'label'       => __( 'Permissions-Policy', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Désactive des fonctions du navigateur que le site n\'utilise pas. Cochez celles à interdire.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'warning'     => __( 'Interdire le paiement ou la géolocalisation casse les extensions qui s\'en servent (boutique, carte de points de vente).', 'graphin-simple-security-ssl' ),
			),
			'hdr_coop'        => array(
				'label'       => __( 'Cross-Origin-Opener-Policy : same-origin', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Isole la fenêtre du site des fenêtres ouvertes par d\'autres domaines.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'warning'     => __( 'Peut casser les fenêtres de connexion et de paiement de services tiers.', 'graphin-simple-security-ssl' ),
			),
			'hdr_xss'         => array(
				'label'       => __( 'X-XSS-Protection : 0', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Désactive l\'ancien filtre des navigateurs, source de failles : bonne pratique actuelle.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'warning'     => '',
			),
		);
	}

	/**
	 * Déclare les valeurs par défaut, même quand le module est inactif.
	 */
	public function __construct() {
		add_filter( 'gsss_default_settings', array( $this, 'defaults' ) );
	}

	/**
	 * Valeurs par défaut : rien n'est envoyé tant qu'une case n'est pas cochée.
	 *
	 * @param array $defaults Valeurs existantes.
	 * @return array
	 */
	public function defaults( $defaults ) {
		return array_merge(
			$defaults,
			array_fill_keys( array_keys( self::options() ), 0 ),
			array(
				'hdr_referrer_value' => 'strict-origin-when-cross-origin',
				'hdr_perm_features'  => array( 'camera', 'microphone', 'geolocation', 'payment', 'usb' ),
				'hdr_csp'            => 0,
				'hdr_csp_mode'       => 'report',
				'hdr_csp_upgrade'    => 0,
			)
		);
	}

	/**
	 * Identifiant.
	 *
	 * @return string
	 */
	public function id() {
		return 'headers';
	}

	/**
	 * Actif dès qu'un en-tête est coché.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		foreach ( array_keys( self::options() ) as $key ) {
			if ( Settings::get( $key ) ) {
				return true;
			}
		}
		return (bool) Settings::get( 'hdr_csp' ) || (bool) Settings::get( 'hdr_csp_upgrade' );
	}

	/**
	 * Réglages cochés par « Appliquer les réglages recommandés ».
	 *
	 * @return array
	 */
	public function recommended() {
		$keys = array();
		foreach ( self::options() as $key => $option ) {
			if ( $option['recommended'] ) {
				$keys[ $key ] = $option['label'];
			}
		}
		return $keys;
	}

	/**
	 * En-têtes simples à envoyer (hors CSP) : nom => valeur.
	 *
	 * @return array
	 */
	public static function simple_headers() {
		$headers = array();
		if ( Settings::get( 'hdr_nosniff' ) ) {
			$headers['X-Content-Type-Options'] = 'nosniff';
		}
		if ( Settings::get( 'hdr_xfo' ) ) {
			$headers['X-Frame-Options'] = 'SAMEORIGIN';
		}
		if ( Settings::get( 'hdr_referrer' ) ) {
			$value                      = (string) Settings::get( 'hdr_referrer_value' );
			$headers['Referrer-Policy'] = in_array( $value, self::referrer_values(), true ) ? $value : 'strict-origin-when-cross-origin';
		}
		if ( Settings::get( 'hdr_permissions' ) ) {
			$chosen = array_values( array_intersect( self::features(), (array) Settings::get( 'hdr_perm_features', array() ) ) );
			if ( ! empty( $chosen ) ) {
				$headers['Permissions-Policy'] = implode( ', ', array_map( array( __CLASS__, 'deny_feature' ), $chosen ) );
			}
		}
		if ( Settings::get( 'hdr_coop' ) ) {
			$headers['Cross-Origin-Opener-Policy'] = 'same-origin';
		}
		if ( Settings::get( 'hdr_xss' ) ) {
			$headers['X-XSS-Protection'] = '0';
		}
		return $headers;
	}

	/**
	 * Écriture d'une fonctionnalité interdite : camera=().
	 *
	 * @param string $feature Fonctionnalité.
	 * @return string
	 */
	public static function deny_feature( $feature ) {
		return $feature . '=()';
	}

	/**
	 * Politique CSP enregistrée, ou celle de départ.
	 *
	 * @return array directive => sources.
	 */
	public static function policy() {
		$policy = get_option( self::POLICY_OPTION );
		return is_array( $policy ) && ! empty( $policy ) ? $policy : self::default_policy();
	}

	/**
	 * Enregistre la politique CSP.
	 *
	 * @param array $policy directive => sources.
	 * @return void
	 */
	public static function save_policy( $policy ) {
		update_option( self::POLICY_OPTION, $policy, false );
	}

	/**
	 * Les règles Apache sont-elles réellement en place ? Sinon PHP envoie les en-têtes.
	 *
	 * @return bool
	 */
	public static function use_php() {
		return Htaccess::served_by_php( 'gsss_headers_via_php' );
	}

	/**
	 * Vérifie que les en-têtes écrits dans .htaccess arrivent vraiment (mod_headers peut manquer :
	 * le bloc <IfModule> est alors ignoré sans erreur). Sinon PHP reprend l'envoi.
	 *
	 * @return bool Vrai si les en-têtes passent par .htaccess.
	 */
	public static function verify_delivery() {
		$expected = self::simple_headers();
		if ( empty( $expected ) || ! Htaccess::rules_served() ) {
			delete_option( 'gsss_headers_via_php' );
			return false;
		}
		// PHP se tait le temps du test, pour ne voir que ce que sert Apache.
		update_option( 'gsss_headers_via_php', 0, true );
		$response  = wp_remote_get(
			add_query_arg( 'gsss_hdr_check', (string) time(), home_url( '/' ) ),
			array(
				'timeout'     => 10,
				'redirection' => 3,
				'user-agent'  => 'Graphin-Simple-Security/' . GSSS_VERSION,
			)
		);
		$name      = (string) key( $expected );
		$delivered = ! is_wp_error( $response ) && '' !== (string) wp_remote_retrieve_header( $response, $name );
		update_option( 'gsss_headers_via_php', $delivered ? 0 : 1, true );
		return $delivered;
	}

	/**
	 * Valeur de la CSP.
	 *
	 * @param bool $enforce Mode appliqué : upgrade-insecure-requests peut y figurer.
	 * @return string
	 */
	public static function csp_value( $enforce ) {
		$parts = array();
		foreach ( self::policy() as $directive => $sources ) {
			$parts[] = $directive . ' ' . implode( ' ', $sources );
		}
		if ( $enforce && Settings::get( 'hdr_csp_upgrade' ) && is_ssl() ) {
			$parts[] = 'upgrade-insecure-requests';
		}
		// report-uri seul : avec report-to, Chrome ignore report-uri et passe par l'API Reporting,
		// dont la livraison n'a pas fonctionné lors des tests. report-uri est compris partout.
		$parts[] = 'report-uri ' . CspReports::endpoint();
		return implode( '; ', $parts );
	}

	/**
	 * Hooks du module.
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'send_headers', array( $this, 'send_headers' ) );
		if ( Settings::get( 'hdr_csp' ) ) {
			add_action( 'rest_api_init', array( 'Graphin\SimpleSecurity\CspReports', 'register_routes' ) );
		}
	}

	/**
	 * Envoie les en-têtes de la requête courante.
	 *
	 * @return void
	 */
	public function send_headers() {
		if ( headers_sent() ) {
			return;
		}
		if ( self::use_php() ) {
			foreach ( self::simple_headers() as $name => $value ) {
				header( $name . ': ' . $value );
			}
		}
		$csp     = Settings::get( 'hdr_csp' ) && ! is_customize_preview();
		$enforce = $csp && 'enforce' === Settings::get( 'hdr_csp_mode' );
		if ( $csp ) {
			header( ( $enforce ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only' ) . ': ' . self::csp_value( $enforce ), false );
		}
		// upgrade-insecure-requests marche seul (comme dans Graph'in Hardening). Dans une CSP en rapport
		// seulement il serait ignoré : il part alors dans un en-tête appliqué à part.
		if ( ! $enforce && Settings::get( 'hdr_csp_upgrade' ) && is_ssl() ) {
			header( 'Content-Security-Policy: upgrade-insecure-requests', false );
		}
	}

	/**
	 * Règles du .htaccess principal : en-têtes simples via mod_headers.
	 *
	 * @return string[]
	 */
	public function htaccess_rules() {
		$headers = self::simple_headers();
		if ( empty( $headers ) ) {
			return array();
		}
		$lines = array( '<IfModule mod_headers.c>' );
		foreach ( $headers as $name => $value ) {
			$lines[] = "\tHeader always set " . $name . ' "' . addcslashes( $value, '"\\' ) . '"';
		}
		$lines[] = '</IfModule>';
		return $lines;
	}
}
