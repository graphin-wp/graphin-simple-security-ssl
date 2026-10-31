<?php
/**
 * Tableau de bord : score, réglages recommandés, export et import, reprise de Graph'in Hardening.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

use Graphin\SimpleSecurity\Login\LoginLimiter;
use Graphin\SimpleSecurity\Login\Twofactor;
use Graphin\SimpleSecurity\Modules\Headers;
use Graphin\SimpleSecurity\Modules\Ssl;
use Graphin\SimpleSecurity\Modules\Vulnerabilities;

defined( 'ABSPATH' ) || exit;

/**
 * Logique du tableau de bord.
 */
class Dashboard {

	const HARDENING_FILE = 'graphin-hardening/graphin-hardening.php';

	/**
	 * Réglages propres à chaque site, jamais exportés ni importés.
	 *
	 * @var string[]
	 */
	private static $site_specific = array( 'ssl_enabled', 'login_url_enabled', 'login_url_slug', 'login_whitelist', 'alert_client', 'client_email' );

	/**
	 * Extensions qui font doublon avec le plugin.
	 *
	 * @var string[]
	 */
	private static $duplicates = array( 'Login Lockdown', 'Limit Login Attempts', 'Loginizer', 'Wordfence', 'Really Simple S', 'Graph\'in Hardening' );

	/**
	 * Page d'administration de chaque module.
	 *
	 * @var array
	 */
	private static $pages = array(
		'ssl'             => 'gsss-ssl',
		'headers'         => 'gsss-headers',
		'vulnerabilities' => 'gsss-vulns',
		'hardening'       => 'gsss-hardening',
		'login'           => 'gsss-login',
	);

	/**
	 * Réglages recommandés des modules : clé => libellé et page.
	 *
	 * @return array
	 */
	public static function recommended() {
		$items = array();
		foreach ( Plugin::instance()->modules() as $id => $module ) {
			foreach ( $module->recommended() as $key => $label ) {
				$items[ $key ] = array(
					'label' => $label,
					'page'  => isset( self::$pages[ $id ] ) ? self::$pages[ $id ] : 'gsss',
				);
			}
		}
		return $items;
	}

	/**
	 * Score : part des points recommandés en place. Le SSL compte, mais s'active depuis sa page.
	 *
	 * @return array percent, done, total, level (ok, warn, ko), items (label, page, done).
	 */
	public static function score() {
		$settings             = Settings::all();
		$items                = self::recommended();
		$items['ssl_enabled'] = array(
			'label' => __( 'Activer le SSL', 'graphin-simple-security-ssl' ),
			'page'  => 'gsss-ssl',
		);
		$done                 = 0;
		foreach ( $items as $key => $item ) {
			$items[ $key ]['done'] = ! empty( $settings[ $key ] );
			$done                 += $items[ $key ]['done'] ? 1 : 0;
		}
		$percent = (int) round( 100 * $done / count( $items ) );
		$level   = 'ko';
		if ( $percent >= 80 ) {
			$level = 'ok';
		} elseif ( $percent >= 50 ) {
			$level = 'warn';
		}
		return array(
			'percent' => $percent,
			'done'    => $done,
			'total'   => count( $items ),
			'level'   => $level,
			'items'   => $items,
		);
	}

	/**
	 * Le site sert-il des adresses http dans ses pages ? Vrai quand le SSL est actif sans correcteur ni Upgrade Insecure Requests.
	 *
	 * @return bool
	 */
	public static function mixed_content_risk() {
		return Settings::get( 'ssl_enabled' ) && ! Settings::get( 'ssl_mixed_front' ) && ! Settings::get( 'hdr_csp_upgrade' );
	}

	/**
	 * Extensions actives qui font doublon.
	 *
	 * @return string[]
	 */
	public static function duplicates() {
		return Plugin::active_plugins_named( self::$duplicates );
	}

	/**
	 * Graph'in Hardening est-il actif ?
	 *
	 * @return bool
	 */
	public static function hardening_active() {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		return is_plugin_active( self::HARDENING_FILE );
	}

	/**
	 * L'adresse du site est-elle déjà en https ?
	 *
	 * @return bool
	 */
	public static function site_is_https() {
		return 0 === stripos( (string) get_option( 'home' ), 'https://' );
	}

	/**
	 * Version disponible du plugin, lue dans les mises à jour connues de WordPress (vide si aucune).
	 *
	 * @return string
	 */
	public static function update_available() {
		$updates  = get_site_transient( 'update_plugins' );
		$basename = plugin_basename( GSSS_FILE );
		return isset( $updates->response[ $basename ]->new_version ) ? (string) $updates->response[ $basename ]->new_version : '';
	}

	/**
	 * Aligne les planifications sur des réglages.
	 *
	 * @param array $settings Réglages complets.
	 * @return void
	 */
	private static function sync_schedules( $settings ) {
		LoginLimiter::sync_schedule( (bool) $settings['login_limit_enabled'] );
		Vulnerabilities::sync_schedule( (bool) $settings['vuln_enabled'] );
	}

	/**
	 * Applique de nouveaux réglages en une écriture, avec les effets d'un premier passage :
	 * IP de l'administrateur en liste blanche, date de départ du délai 2FA.
	 * Puis planifications et .htaccess, avec retour à l'état d'avant si le site casse.
	 *
	 * @param array $values Clé => valeur.
	 * @param bool  $verify Vérifier ensuite ce que sert Apache.
	 * @return true|\WP_Error
	 */
	private static function commit( $values, $verify = true ) {
		$previous = Settings::all();
		Settings::set_many( $values );
		if ( Settings::get( 'login_limit_enabled' ) && ! $previous['login_limit_enabled'] ) {
			Settings::set( 'login_whitelist', LoginLimiter::with_own_ip( (array) Settings::get( 'login_whitelist', array() ) ) );
		}
		Twofactor::sync_enforce_since( (bool) $previous['login_2fa_enforce'] );
		self::sync_schedules( Settings::all() );
		$sync = Htaccess::sync_or_restore(
			function () use ( $previous ) {
				update_option( Settings::OPTION, $previous, false );
				Twofactor::sync_enforce_since( (bool) $previous['login_2fa_enforce'] );
				self::sync_schedules( $previous );
			}
		);
		if ( $verify && ! Htaccess::is_rollback( $sync ) ) {
			self::verify();
		}
		return is_wp_error( $sync ) ? $sync : true;
	}

	/**
	 * Vérifie que les en-têtes, et la redirection si le SSL est actif, sont servis par Apache.
	 *
	 * @return void
	 */
	private static function verify() {
		Headers::verify_delivery();
		if ( Settings::get( 'ssl_enabled' ) ) {
			Ssl::verify_delivery();
		}
	}

	/**
	 * Coche tous les réglages recommandés, en une seule écriture de .htaccess.
	 *
	 * @return true|\WP_Error
	 */
	public static function apply_recommended() {
		$result = self::commit( array_fill_keys( array_keys( self::recommended() ), 1 ) );
		if ( ! Htaccess::is_rollback( $result ) ) {
			Logger::log( 'recommended_applied', __( 'Réglages recommandés appliqués.', 'graphin-simple-security-ssl' ), array(), 'warning' );
		}
		return $result;
	}

	/**
	 * Reprend Graph'in Hardening : mêmes en-têtes et mêmes mesures, puis le désactive.
	 * Si le site est déjà en https, le SSL est activé pour garder HSTS.
	 *
	 * @return string|\WP_Error Suffixe du message : '' (HSTS repris), '_http' (site en http) ou '_nossl' (SSL refusé).
	 */
	public static function take_over_hardening() {
		if ( ! self::hardening_active() ) {
			return new \WP_Error( 'not_active', '' );
		}
		$values = array_fill_keys( array( 'hdr_nosniff', 'hdr_xfo', 'hdr_referrer', 'hdr_xss', 'hdr_csp_upgrade', 'hard_xmlrpc', 'hard_pingbacks', 'hard_opcache_notice' ), 1 );
		if ( ! Settings::get( 'hdr_referrer' ) ) {
			$values['hdr_referrer_value'] = 'strict-origin-when-cross-origin';
		}
		// Une politique déjà réglée ici est gardée ; sinon, celle de Graph'in Hardening.
		if ( ! Settings::get( 'hdr_permissions' ) ) {
			$values['hdr_permissions']   = 1;
			$values['hdr_perm_features'] = array( 'camera', 'microphone', 'geolocation' );
		}
		$https = self::site_is_https();
		if ( $https ) {
			$values['ssl_hsts'] = 1;
		}
		$result = self::commit( $values, false );
		if ( Htaccess::is_rollback( $result ) ) {
			return $result;
		}
		// Désactivé avant toute vérification, pour que ses en-têtes PHP ne se mêlent pas à ceux d'Apache.
		deactivate_plugins( self::HARDENING_FILE );
		if ( $https && ! Settings::get( 'ssl_enabled' ) ) {
			// Ssl::enable() vérifie lui-même la redirection et HSTS.
			$suffix = is_wp_error( Ssl::enable() ) ? '_nossl' : '';
			Headers::verify_delivery();
		} else {
			$suffix = $https ? '' : '_http';
			self::verify();
		}
		Logger::log( 'hardening_taken_over', __( 'Graph\'in Hardening repris puis désactivé.', 'graphin-simple-security-ssl' ), array( 'hsts' => '' === $suffix ), 'warning' );
		return $suffix;
	}

	/**
	 * Réglages à exporter, sans ce qui est propre au site.
	 *
	 * @return array
	 */
	public static function export() {
		return array(
			'plugin'   => 'graphin-simple-security-ssl',
			'version'  => GSSS_VERSION,
			'exported' => gmdate( 'c' ),
			'settings' => array_diff_key( Settings::all(), array_flip( self::$site_specific ) ),
		);
	}

	/**
	 * Contrôle une valeur importée. Null : valeur refusée.
	 *
	 * @param string $key      Clé connue.
	 * @param mixed  $value    Valeur du fichier.
	 * @param mixed  $fallback Valeur par défaut, qui donne le type.
	 * @return mixed
	 */
	private static function clean( $key, $value, $fallback ) {
		if ( is_array( $value ) !== is_array( $fallback ) ) {
			return null;
		}
		switch ( $key ) {
			case 'ssl_www':
				return in_array( $value, Ssl::WWW_CHOICES, true ) && Ssl::www_matches( $value ) ? $value : null;
			case 'hdr_referrer_value':
				return in_array( $value, Headers::referrer_values(), true ) ? $value : null;
			case 'hdr_perm_features':
				return array_values( array_intersect( Headers::features(), $value ) );
			case 'vuln_min_severity':
				return in_array( $value, VulnScanner::SEVERITIES, true ) ? $value : null;
			case 'hdr_csp_mode':
				// La politique CSP n'est pas exportée : sur un autre site, elle repart en rapport seulement.
				return 'report';
			case 'login_2fa_enabled':
				return Crypto::available() ? $value : 0;
		}
		return $value;
	}

	/**
	 * Importe des réglages exportés. Les clés inconnues et les réglages propres au site sont ignorés.
	 *
	 * @param string $json Contenu du fichier.
	 * @return int|\WP_Error Nombre de réglages importés.
	 */
	public static function import( $json ) {
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || ! isset( $data['plugin'], $data['settings'] ) || 'graphin-simple-security-ssl' !== $data['plugin'] || ! is_array( $data['settings'] ) ) {
			return new \WP_Error( 'invalid', '' );
		}
		$defaults = Settings::defaults();
		$values   = array();
		foreach ( array_diff_key( array_intersect_key( $data['settings'], $defaults ), array_flip( self::$site_specific ) ) as $key => $value ) {
			$value = self::clean( $key, $value, $defaults[ $key ] );
			if ( null !== $value ) {
				$values[ $key ] = $value;
			}
		}
		$result = self::commit( $values );
		if ( Htaccess::is_rollback( $result ) ) {
			return $result;
		}
		/* translators: %d: nombre de réglages */
		Logger::log( 'settings_imported', sprintf( __( 'Réglages importés : %d.', 'graphin-simple-security-ssl' ), count( $values ) ), array( 'from' => isset( $data['version'] ) ? sanitize_text_field( (string) $data['version'] ) : '' ), 'warning' );
		return count( $values );
	}
}
