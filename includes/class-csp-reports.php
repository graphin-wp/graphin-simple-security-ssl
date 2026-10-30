<?php
/**
 * Rapports de violation CSP : endpoint REST public, stockage plafonné, « Autoriser ».
 *
 * L'endpoint est public par nature (les navigateurs n'envoient aucun identifiant) : taille,
 * débit, formats et contenu sont donc strictement bornés, et les domaines ne sont jamais
 * considérés comme fiables tant qu'un administrateur ne les a pas autorisés.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

use Graphin\SimpleSecurity\Login\LoginLimiter;
use Graphin\SimpleSecurity\Modules\Headers;

defined( 'ABSPATH' ) || exit;

/**
 * Collecte des violations de la politique de sécurité de contenu.
 */
class CspReports {

	const OPTION         = 'gsss_csp_reports';
	const MAX_ROWS       = 100;
	const MAX_BODY       = 16384;
	const RATE_MAX       = 30;
	const RATE_TTL       = 60;
	const REST_NAMESPACE = 'gsss/v1';
	const ROUTE          = '/csp-report';

	/**
	 * Directives acceptées (les variantes -elem et -attr sont ramenées à leur base).
	 *
	 * @var string[]
	 */
	private static $directives = array( 'default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'frame-src', 'child-src', 'media-src', 'object-src', 'worker-src', 'manifest-src' );

	/**
	 * Adresse de l'endpoint.
	 *
	 * @return string
	 */
	public static function endpoint() {
		return rest_url( self::REST_NAMESPACE . self::ROUTE );
	}

	/**
	 * Déclare la route.
	 *
	 * @return void
	 */
	public static function register_routes() {
		register_rest_route(
			self::REST_NAMESPACE,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'handle' ),
				'permission_callback' => '__return_true', // Public par nature : voir l'en-tête du fichier.
			)
		);
	}

	/**
	 * Reçoit un rapport (formats application/csp-report et application/reports+json).
	 *
	 * @param \WP_REST_Request $request Requête.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public static function handle( $request ) {
		$ip  = LoginLimiter::client_ip();
		$key = 'gsss_csprl_' . md5( $ip );
		$hit = (int) get_transient( $key );
		if ( $hit >= self::RATE_MAX ) {
			return new \WP_Error( 'gsss_rate', 'Too many reports.', array( 'status' => 429 ) );
		}
		set_transient( $key, $hit + 1, self::RATE_TTL );

		$body = (string) $request->get_body();
		if ( strlen( $body ) > self::MAX_BODY ) {
			return new \WP_Error( 'gsss_size', 'Payload too large.', array( 'status' => 413 ) );
		}
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return new \WP_Error( 'gsss_json', 'Invalid report.', array( 'status' => 400 ) );
		}

		foreach ( self::extract( $data ) as $report ) {
			self::store( $report );
		}
		return new \WP_REST_Response( null, 204 );
	}

	/**
	 * Ramène les deux formats à une liste de rapports bruts.
	 *
	 * @param array $data JSON décodé.
	 * @return array[] directive, blocked, doc.
	 */
	private static function extract( $data ) {
		$reports = array();
		if ( isset( $data['csp-report'] ) && is_array( $data['csp-report'] ) ) {
			$r         = $data['csp-report'];
			$reports[] = array(
				'directive' => isset( $r['effective-directive'] ) ? $r['effective-directive'] : ( isset( $r['violated-directive'] ) ? $r['violated-directive'] : '' ),
				'blocked'   => isset( $r['blocked-uri'] ) ? $r['blocked-uri'] : '',
				'doc'       => isset( $r['document-uri'] ) ? $r['document-uri'] : '',
			);
		} elseif ( isset( $data[0] ) ) {
			foreach ( array_slice( $data, 0, 10 ) as $item ) {
				if ( is_array( $item ) && isset( $item['body'] ) && is_array( $item['body'] ) && ( ! isset( $item['type'] ) || 'csp-violation' === $item['type'] ) ) {
					$b         = $item['body'];
					$reports[] = array(
						'directive' => isset( $b['effectiveDirective'] ) ? $b['effectiveDirective'] : '',
						'blocked'   => isset( $b['blockedURL'] ) ? $b['blockedURL'] : '',
						'doc'       => isset( $b['documentURL'] ) ? $b['documentURL'] : '',
					);
				}
			}
		}
		return $reports;
	}

	/**
	 * Nettoie un rapport et l'enregistre (dédoublonné par directive et source).
	 *
	 * @param array $report Rapport brut.
	 * @return void
	 */
	private static function store( $report ) {
		if ( ! is_string( $report['directive'] ) || ! is_string( $report['blocked'] ) || ! is_string( $report['doc'] ) ) {
			return;
		}
		$directive = preg_replace( '/-(elem|attr)$/', '', strtolower( trim( strtok( $report['directive'] . ' ', ' ' ) ) ) );
		if ( ! in_array( $directive, self::$directives, true ) ) {
			return;
		}
		$source = self::source_of( $report['blocked'] );
		if ( null === $source ) {
			return;
		}
		$path = (string) wp_parse_url( $report['doc'], PHP_URL_PATH );
		$path = '' === $path ? '/' : substr( preg_replace( '/[^A-Za-z0-9\-._~\/%]/', '', $path ), 0, 120 );

		$rows = get_option( self::OPTION, array() );
		$rows = is_array( $rows ) ? $rows : array();
		$id   = md5( $directive . '|' . $source['value'] );
		$now  = time();
		if ( isset( $rows[ $id ] ) ) {
			$rows[ $id ]['count'] = (int) $rows[ $id ]['count'] + 1;
			$rows[ $id ]['last']  = $now;
		} else {
			if ( count( $rows ) >= self::MAX_ROWS ) {
				uasort(
					$rows,
					function ( $a, $b ) {
						return (int) $a['last'] - (int) $b['last'];
					}
				);
				array_shift( $rows );
			}
			$rows[ $id ] = array(
				'directive' => $directive,
				'source'    => $source['value'],
				'kind'      => $source['kind'],
				'doc'       => $path,
				'count'     => 1,
				'first'     => $now,
				'last'      => $now,
			);
		}
		update_option( self::OPTION, $rows, false );
	}

	/**
	 * Source CSP déduite de l'adresse bloquée.
	 *
	 * @param string $blocked Valeur de blocked-uri.
	 * @return array|null value, kind (host, scheme, keyword), ou null si inutilisable.
	 */
	private static function source_of( $blocked ) {
		$blocked = strtolower( trim( $blocked ) );
		if ( in_array( $blocked, array( 'inline', 'eval' ), true ) ) {
			return array(
				'value' => $blocked,
				'kind'  => 'keyword',
			);
		}
		if ( in_array( $blocked, array( 'data', 'blob' ), true ) ) {
			return array(
				'value' => $blocked . ':',
				'kind'  => 'scheme',
			);
		}
		$parts = wp_parse_url( $blocked );
		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) || ! in_array( $parts['scheme'], array( 'http', 'https', 'ws', 'wss' ), true ) ) {
			return null;
		}
		$host = $parts['host'];
		if ( strlen( $host ) > 253 || ! preg_match( '/^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$/', $host ) ) {
			return null;
		}
		return array(
			'value' => $parts['scheme'] . '://' . $host,
			'kind'  => 'host',
		);
	}

	/**
	 * Rapports enregistrés, le plus récent d'abord.
	 *
	 * @return array id => rapport.
	 */
	public static function all() {
		$rows = get_option( self::OPTION, array() );
		$rows = is_array( $rows ) ? $rows : array();
		uasort(
			$rows,
			function ( $a, $b ) {
				return (int) $b['last'] - (int) $a['last'];
			}
		);
		return $rows;
	}

	/**
	 * Supprime tous les rapports.
	 *
	 * @return void
	 */
	public static function clear() {
		delete_option( self::OPTION );
	}

	/**
	 * Ajoute à la politique la source d'un rapport, puis supprime ce rapport.
	 *
	 * @param string $id Identifiant du rapport.
	 * @return true|string Vrai, ou un code d'erreur : unknown, keyword.
	 */
	public static function allow( $id ) {
		$rows = self::all();
		if ( ! isset( $rows[ $id ] ) ) {
			return 'unknown';
		}
		$row = $rows[ $id ];
		if ( 'keyword' === $row['kind'] ) {
			return 'keyword';
		}
		$policy    = Headers::policy();
		$directive = $row['directive'];
		if ( ! isset( $policy[ $directive ] ) ) {
			// Une directive absente retombe sur default-src : on la crée en gardant 'self'.
			$policy[ $directive ] = array( "'self'" );
		}
		if ( ! in_array( $row['source'], $policy[ $directive ], true ) ) {
			$policy[ $directive ][] = $row['source'];
		}
		Headers::save_policy( $policy );
		unset( $rows[ $id ] );
		update_option( self::OPTION, $rows, false );
		return true;
	}
}
