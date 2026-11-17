<?php
/**
 * Client WPVulnerability : récupération, filtrage par version, scan par lots.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Analyse des plugins, thèmes et du cœur.
 */
class VulnScanner {

	const API_BASE        = 'https://www.wpvulnerability.net/';
	const CACHE_TTL       = 43200; // 12 h.
	const STATE_OPTION    = 'gsss_vuln_scan';
	const RESULTS_OPTION  = 'gsss_vuln_results';
	const BATCH           = 10;
	const PAUSE_MICROSEC  = 300000;
	const DESCRIPTION_MAX = 220;
	const SEVERITIES      = array( 'low', 'medium', 'high', 'critical' );

	/**
	 * Rang d'une gravité, pour comparer et trier.
	 *
	 * @param string $severity critical, high, medium ou low.
	 * @return int
	 */
	public static function rank( $severity ) {
		$ranks = array(
			'low'      => 1,
			'medium'   => 2,
			'high'     => 3,
			'critical' => 4,
		);
		return isset( $ranks[ $severity ] ) ? $ranks[ $severity ] : 2;
	}

	/**
	 * Libellé français d'une gravité.
	 *
	 * @param string $severity Gravité.
	 * @return string
	 */
	public static function label( $severity ) {
		$labels = array(
			'low'      => __( 'Faible', 'graphin-simple-security-ssl' ),
			'medium'   => __( 'Moyenne', 'graphin-simple-security-ssl' ),
			'high'     => __( 'Élevée', 'graphin-simple-security-ssl' ),
			'critical' => __( 'Critique', 'graphin-simple-security-ssl' ),
		);
		return isset( $labels[ $severity ] ) ? $labels[ $severity ] : $labels['medium'];
	}

	/**
	 * Composants installés : plugins, thèmes, cœur.
	 *
	 * @return array[] Chaque élément : type, slug, name, version.
	 */
	public static function components() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$list = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( '' === (string) $data['Version'] ) {
				continue;
			}
			$dir    = dirname( $file );
			$list[] = array(
				'type'    => 'plugin',
				'slug'    => sanitize_key( '.' === $dir ? basename( $file, '.php' ) : $dir ),
				'name'    => $data['Name'],
				'version' => $data['Version'],
			);
		}
		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			$version = (string) $theme->get( 'Version' );
			if ( '' === $version ) {
				continue;
			}
			$list[] = array(
				'type'    => 'theme',
				'slug'    => sanitize_key( $stylesheet ),
				'name'    => (string) $theme->get( 'Name' ),
				'version' => $version,
			);
		}
		$list[] = array(
			'type'    => 'core',
			'slug'    => 'core',
			'name'    => 'WordPress',
			'version' => get_bloginfo( 'version' ),
		);
		return $list;
	}

	/**
	 * Gravité d'une faille d'après le score CVSS.
	 *
	 * @param array $vuln Faille brute de l'API.
	 * @return string
	 */
	private static function severity_of( $vuln ) {
		$impact = isset( $vuln['impact'] ) && is_array( $vuln['impact'] ) ? $vuln['impact'] : array();
		if ( isset( $impact['cvss3']['severity'] ) ) {
			$name = strtolower( (string) $impact['cvss3']['severity'] );
			if ( in_array( $name, array( 'critical', 'high', 'medium', 'low' ), true ) ) {
				return $name;
			}
		}
		$score = 0.0;
		if ( isset( $impact['cvss3']['score'] ) ) {
			$score = (float) $impact['cvss3']['score'];
		} elseif ( isset( $impact['cvss']['score'] ) ) {
			$score = (float) $impact['cvss']['score'];
		}
		if ( $score >= 9 ) {
			return 'critical';
		}
		if ( $score >= 7 ) {
			return 'high';
		}
		if ( $score >= 4 ) {
			return 'medium';
		}
		return $score > 0 ? 'low' : 'medium';
	}

	/**
	 * Description courte en texte brut (l'API est traitée comme non fiable).
	 *
	 * @param array $vuln Faille brute.
	 * @return string
	 */
	private static function description_of( $vuln ) {
		$text = isset( $vuln['description'] ) ? (string) $vuln['description'] : '';
		if ( '' === $text && ! empty( $vuln['source'][0]['description'] ) ) {
			$text = (string) $vuln['source'][0]['description'];
		}
		if ( '' === $text && ! empty( $vuln['name'] ) ) {
			$text = (string) $vuln['name'];
		}
		$text = preg_replace( '/^\[[a-z]{2}\]\s*/', '', wp_strip_all_tags( wp_specialchars_decode( $text, ENT_QUOTES ) ) );
		$text = sanitize_text_field( $text );
		return strlen( $text ) > self::DESCRIPTION_MAX ? rtrim( substr( $text, 0, self::DESCRIPTION_MAX ) ) . '…' : $text;
	}

	/**
	 * Premier lien http(s) valide parmi les sources.
	 *
	 * @param array $vuln Faille brute.
	 * @return string
	 */
	private static function link_of( $vuln ) {
		if ( ! empty( $vuln['source'] ) && is_array( $vuln['source'] ) ) {
			foreach ( $vuln['source'] as $source ) {
				if ( ! empty( $source['link'] ) ) {
					$url = esc_url_raw( (string) $source['link'], array( 'http', 'https' ) );
					if ( '' !== $url ) {
						return $url;
					}
				}
			}
		}
		return '';
	}

	/**
	 * Réduit la réponse de l'API à ce qu'on stocke.
	 *
	 * @param array $data Champ data de la réponse.
	 * @return array vulns, closed.
	 */
	private static function normalise( $data ) {
		$vulns = array();
		if ( ! empty( $data['vulnerability'] ) && is_array( $data['vulnerability'] ) ) {
			foreach ( $data['vulnerability'] as $vuln ) {
				if ( ! is_array( $vuln ) ) {
					continue;
				}
				$op      = isset( $vuln['operator'] ) && is_array( $vuln['operator'] ) ? $vuln['operator'] : array();
				$vulns[] = array(
					'id'          => isset( $vuln['uuid'] ) ? sanitize_key( (string) $vuln['uuid'] ) : md5( wp_json_encode( $vuln ) ),
					'min'         => isset( $op['min_version'] ) && '' !== (string) $op['min_version'] ? sanitize_text_field( (string) $op['min_version'] ) : null,
					'min_op'      => isset( $op['min_operator'] ) ? sanitize_key( (string) $op['min_operator'] ) : '',
					'max'         => isset( $op['max_version'] ) && '' !== (string) $op['max_version'] ? sanitize_text_field( (string) $op['max_version'] ) : null,
					'max_op'      => isset( $op['max_operator'] ) ? sanitize_key( (string) $op['max_operator'] ) : '',
					'unfixed'     => ! empty( $op['unfixed'] ) && '0' !== (string) $op['unfixed'],
					'severity'    => self::severity_of( $vuln ),
					'description' => self::description_of( $vuln ),
					'link'        => self::link_of( $vuln ),
				);
			}
		}
		return array(
			'vulns'  => $vulns,
			'closed' => array(
				'closed' => ! empty( $data['closed'] ) && '0' !== (string) $data['closed'],
				'reason' => isset( $data['closed_reason'] ) ? sanitize_text_field( (string) $data['closed_reason'] ) : '',
				'date'   => isset( $data['closed_date'] ) ? sanitize_text_field( (string) $data['closed_date'] ) : '',
			),
		);
	}

	/**
	 * Interroge l'API (cache de 12 h). Seul le slug part sur le réseau (cœur : la version).
	 *
	 * @param array $comp Composant.
	 * @return array|\WP_Error
	 */
	public static function fetch( $comp ) {
		$param  = 'core' === $comp['type'] ? $comp['version'] : $comp['slug'];
		$key    = 'gsss_vuln_' . md5( $comp['type'] . '|' . $param );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			self::API_BASE . $comp['type'] . '/' . rawurlencode( $param ) . '/',
			array(
				'timeout'    => 15,
				'headers'    => array( 'Accept' => 'application/json' ),
				// L'agent par défaut de WordPress contient l'adresse du site : on ne l'envoie pas.
				'user-agent' => 'Graphin-Simple-Security/' . GSSS_VERSION,
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) || ! is_array( $body ) || ! empty( $body['error'] ) || ! isset( $body['data'] ) || ! is_array( $body['data'] ) ) {
			return new \WP_Error( 'gsss_vuln_api', __( 'Réponse inattendue de WPVulnerability.', 'graphin-simple-security-ssl' ) );
		}
		$data = self::normalise( $body['data'] );
		set_transient( $key, $data, self::CACHE_TTL );
		return $data;
	}

	/**
	 * La version installée est-elle concernée par cette faille ?
	 * WPVulnerability donne une borne basse et une borne haute, chacune avec un opérateur :
	 * ge, gt, lt, le, et aussi eq (une seule version touchée) ou ne.
	 * Opérateur inconnu : la borne est ignorée et la version reste concernée (mieux vaut un faux positif).
	 *
	 * @param string $version Version installée.
	 * @param array  $vuln    Faille normalisée.
	 * @return bool
	 */
	public static function is_affected( $version, $vuln ) {
		$map = array(
			'ge' => '>=',
			'gt' => '>',
			'lt' => '<',
			'le' => '<=',
			'eq' => '==',
			'ne' => '!=',
		);
		if ( null !== $vuln['min'] && isset( $map[ $vuln['min_op'] ] ) && ! version_compare( $version, $vuln['min'], $map[ $vuln['min_op'] ] ) ) {
			return false;
		}
		if ( null !== $vuln['max'] && isset( $map[ $vuln['max_op'] ] ) && ! version_compare( $version, $vuln['max'], $map[ $vuln['max_op'] ] ) ) {
			return false;
		}
		return true;
	}

	/**
	 * Analyse un composant.
	 *
	 * @param array $comp Composant.
	 * @return array|\WP_Error findings, closed.
	 */
	public static function scan_component( $comp ) {
		$data = self::fetch( $comp );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		$findings = array();
		foreach ( $data['vulns'] as $vuln ) {
			if ( ! self::is_affected( $comp['version'], $vuln ) ) {
				continue;
			}
			$findings[] = array(
				'id'          => md5( $comp['type'] . ':' . $comp['slug'] . ':' . $vuln['id'] ),
				'type'        => $comp['type'],
				'slug'        => $comp['slug'],
				'name'        => $comp['name'],
				'version'     => $comp['version'],
				'severity'    => $vuln['severity'],
				'description' => $vuln['description'],
				'fixed'       => ( 'lt' === $vuln['max_op'] && ! $vuln['unfixed'] && null !== $vuln['max'] ) ? $vuln['max'] : '',
				'link'        => $vuln['link'],
			);
		}
		$closed = array();
		if ( $data['closed']['closed'] ) {
			$closed = array(
				'type'   => $comp['type'],
				'slug'   => $comp['slug'],
				'name'   => $comp['name'],
				'reason' => $data['closed']['reason'],
				'date'   => $data['closed']['date'],
			);
		}
		return array(
			'findings' => $findings,
			'closed'   => $closed,
		);
	}

	/**
	 * Dernier résultat enregistré.
	 *
	 * @return array time, findings, closed, errors.
	 */
	public static function results() {
		$results = get_option( self::RESULTS_OPTION );
		if ( ! is_array( $results ) ) {
			$results = array();
		}
		return array_merge(
			array(
				'time'     => 0,
				'findings' => array(),
				'closed'   => array(),
				'errors'   => 0,
			),
			$results
		);
	}

	/**
	 * Abandonne un scan en cours.
	 *
	 * @return void
	 */
	public static function reset() {
		delete_option( self::STATE_OPTION );
	}

	/**
	 * Traite un lot de composants. Démarre un scan s'il n'y en a pas en cours.
	 *
	 * @param int $batch Nombre de composants par lot.
	 * @return array done, processed, total, errors (et count quand c'est fini).
	 */
	public static function step( $batch = self::BATCH ) {
		$state = get_option( self::STATE_OPTION );
		if ( ! is_array( $state ) ) {
			$queue = self::components();
			$state = array(
				'queue'    => $queue,
				'total'    => count( $queue ),
				'findings' => array(),
				'closed'   => array(),
				'failed'   => array(),
			);
		}

		$count = 0;
		while ( $count < $batch && ! empty( $state['queue'] ) ) {
			$comp = array_shift( $state['queue'] );
			if ( $count > 0 ) {
				usleep( self::PAUSE_MICROSEC );
			}
			$result = self::scan_component( $comp );
			if ( is_wp_error( $result ) ) {
				$state['failed'][] = $comp['type'] . ':' . $comp['slug'];
			} else {
				$state['findings'] = array_merge( $state['findings'], $result['findings'] );
				if ( ! empty( $result['closed'] ) ) {
					$state['closed'][] = $result['closed'];
				}
			}
			++$count;
		}

		if ( empty( $state['queue'] ) ) {
			return self::finalize( $state );
		}
		update_option( self::STATE_OPTION, $state, false );
		return array(
			'done'      => false,
			'processed' => $state['total'] - count( $state['queue'] ),
			'total'     => $state['total'],
			'errors'    => count( $state['failed'] ),
		);
	}

	/**
	 * Enregistre le résultat. Les failles connues d'un composant dont l'appel a échoué sont conservées.
	 *
	 * @param array $state État du scan.
	 * @return array
	 */
	private static function finalize( $state ) {
		$findings = $state['findings'];
		if ( ! empty( $state['failed'] ) ) {
			foreach ( self::results()['findings'] as $old ) {
				if ( in_array( $old['type'] . ':' . $old['slug'], $state['failed'], true ) ) {
					$findings[] = $old;
				}
			}
		}
		usort(
			$findings,
			function ( $a, $b ) {
				return self::rank( $b['severity'] ) - self::rank( $a['severity'] );
			}
		);

		$errors = count( $state['failed'] );
		update_option(
			self::RESULTS_OPTION,
			array(
				'time'     => time(),
				'findings' => $findings,
				'closed'   => $state['closed'],
				'errors'   => $errors,
			),
			false
		);
		delete_option( self::STATE_OPTION );

		/**
		 * Fin d'un scan.
		 *
		 * @param array $findings   Failles trouvées.
		 * @param bool  $had_errors Au moins un composant n'a pas pu être interrogé.
		 */
		do_action( 'gsss_vuln_scan_complete', $findings, $errors > 0 );

		return array(
			'done'      => true,
			'processed' => $state['total'],
			'total'     => $state['total'],
			'errors'    => $errors,
			'count'     => count( $findings ),
		);
	}
}
