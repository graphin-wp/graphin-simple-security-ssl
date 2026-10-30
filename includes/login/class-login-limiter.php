<?php
/**
 * Limitation des tentatives de connexion, par IP.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Login;

use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Compteur d'échecs, blocage progressif, liste blanche.
 */
class LoginLimiter {

	const DB_VERSION  = '1';
	const HOOK_PURGE  = 'gsss_login_purge';
	const MAX_BLOCK   = 86400;
	const IDLE_PURGE  = 172800;
	const BLOCK_CODE  = 'gsss_login_blocked';
	const UNBLOCK_ACT = 'gsss_login_unblock';

	/**
	 * Extensions de limitation qui font déjà ce travail.
	 *
	 * @var string[]
	 */
	private static $other_limiters = array( 'Login Lockdown', 'Limit Login Attempts', 'Loginizer', 'Wordfence' );

	/**
	 * Nom complet de la table.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'gsss_login_attempts';
	}

	/**
	 * Crée la table.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
				ip varchar(45) NOT NULL,
				fails int(10) unsigned NOT NULL DEFAULT 0,
				first_fail bigint(20) unsigned NOT NULL DEFAULT 0,
				last_fail bigint(20) unsigned NOT NULL DEFAULT 0,
				blocked_until bigint(20) unsigned NOT NULL DEFAULT 0,
				strikes int(10) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (ip)
			) {$charset};"
		);
		update_option( 'gsss_login_db_version', self::DB_VERSION, false );
	}

	/**
	 * Branche les hooks du bloc.
	 *
	 * @return void
	 */
	public function register_hooks() {
		if ( get_option( 'gsss_login_db_version' ) !== self::DB_VERSION ) {
			self::install();
		}
		// Après les vérifications du cœur (priorités 20 à 30) et avant le second facteur (100).
		add_filter( 'authenticate', array( $this, 'block_if_limited' ), 90, 1 );
		add_action( 'wp_login_failed', array( $this, 'record_failure' ) );
		add_action( 'wp_login', array( $this, 'record_success' ) );
		add_action( self::HOOK_PURGE, array( __CLASS__, 'purge' ) );
		add_action( 'admin_post_' . self::UNBLOCK_ACT, array( $this, 'action_unblock' ) );
		self::sync_schedule( true );
	}

	/**
	 * Planifie ou retire la purge quotidienne.
	 *
	 * @param bool $enabled Bloc actif.
	 * @return void
	 */
	public static function sync_schedule( $enabled ) {
		if ( $enabled ) {
			if ( ! wp_next_scheduled( self::HOOK_PURGE ) ) {
				wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::HOOK_PURGE );
			}
			return;
		}
		self::clear_schedule();
	}

	/**
	 * Retire la purge quotidienne (désactivation du plugin ou du bloc).
	 *
	 * @return void
	 */
	public static function clear_schedule() {
		wp_clear_scheduled_hook( self::HOOK_PURGE );
	}

	/**
	 * Forme canonique d'une adresse IP.
	 *
	 * @param string $ip Adresse.
	 * @return string Chaîne vide si l'adresse est invalide.
	 */
	public static function normalize_ip( $ip ) {
		$ip = trim( (string) $ip );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$packed = inet_pton( $ip );
		return false === $packed ? '' : (string) inet_ntop( $packed );
	}

	/**
	 * IP du visiteur. Derrière un proxy (case cochée) : dernière adresse de X-Forwarded-For,
	 * celle qu'ajoute le proxy. La première peut être choisie par le visiteur.
	 *
	 * @return string
	 */
	public static function client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( Settings::get( 'login_proxy' ) && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
			$last  = self::normalize_ip( end( $parts ) );
			if ( '' !== $last ) {
				$ip = $last;
			}
		}
		/**
		 * Permet d'adapter la détection de l'IP (plusieurs proxys, en-tête de CDN).
		 *
		 * @param string $ip Adresse détectée.
		 */
		return self::normalize_ip( apply_filters( 'gsss_client_ip', $ip ) );
	}

	/**
	 * L'IP est-elle dans la liste blanche ?
	 *
	 * @param string $ip Adresse normalisée.
	 * @return bool
	 */
	public static function is_whitelisted( $ip ) {
		$list = Settings::get( 'login_whitelist', array() );
		return is_array( $list ) && in_array( $ip, $list, true );
	}

	/**
	 * Ligne d'une IP.
	 *
	 * @param string $ip Adresse normalisée.
	 * @return array|null
	 */
	private static function row( $ip ) {
		global $wpdb;
		$table = self::table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE ip = %s", $ip ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Table interne.
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Secondes restantes avant la fin du blocage d'une IP.
	 *
	 * @param string $ip Adresse normalisée.
	 * @return int 0 si l'IP n'est pas bloquée.
	 */
	public static function remaining( $ip ) {
		$row = self::row( $ip );
		return ( $row && (int) $row['blocked_until'] > time() ) ? (int) $row['blocked_until'] - time() : 0;
	}

	/**
	 * Refuse la connexion d'une IP bloquée, même avec le bon mot de passe.
	 *
	 * @param \WP_User|\WP_Error|null $user Résultat de l'authentification.
	 * @return \WP_User|\WP_Error|null
	 */
	public function block_if_limited( $user ) {
		$ip = self::client_ip();
		if ( '' === $ip || self::is_whitelisted( $ip ) ) {
			return $user;
		}
		$left = self::remaining( $ip );
		if ( $left > 0 ) {
			/* translators: %d: minutes */
			return new \WP_Error( self::BLOCK_CODE, sprintf( _n( '<strong>Erreur :</strong> trop de tentatives. Réessayez dans %d minute.', '<strong>Erreur :</strong> trop de tentatives. Réessayez dans %d minutes.', (int) ceil( $left / 60 ), 'graphin-simple-security-ssl' ), (int) ceil( $left / 60 ) ) );
		}
		return $user;
	}

	/**
	 * Compte un échec de connexion, et bloque l'IP au-delà du seuil.
	 * Lecture puis écriture : une rafale simultanée peut laisser passer une tentative de plus.
	 *
	 * @return void
	 */
	public function record_failure() {
		global $wpdb;
		$ip = self::client_ip();
		if ( '' === $ip || self::is_whitelisted( $ip ) ) {
			return;
		}
		$now    = time();
		$max    = max( 1, (int) Settings::get( 'login_limit_attempts', 5 ) );
		$window = max( 1, (int) Settings::get( 'login_limit_window', 15 ) ) * MINUTE_IN_SECONDS;
		$base   = max( 1, (int) Settings::get( 'login_limit_block', 30 ) ) * MINUTE_IN_SECONDS;
		$row    = self::row( $ip );

		if ( $row && (int) $row['blocked_until'] > $now ) {
			return;
		}
		if ( $row ) {
			$expired = ( $now - (int) $row['first_fail'] ) > $window;
			$fails   = $expired ? 1 : (int) $row['fails'] + 1;
			$first   = $expired ? $now : (int) $row['first_fail'];
			$strikes = (int) $row['strikes'];
		} else {
			$fails   = 1;
			$first   = $now;
			$strikes = 0;
		}

		$blocked_until = 0;
		if ( $fails >= $max ) {
			++$strikes;
			$duration      = (int) min( self::MAX_BLOCK, $base * ( 2 ** ( $strikes - 1 ) ) );
			$blocked_until = $now + $duration;
			$fails         = 0;
			$first         = 0;
			Logger::log(
				'login_blocked',
				/* translators: 1: adresse IP, 2: minutes */
				sprintf( __( 'IP bloquée : %1$s pendant %2$d minutes.', 'graphin-simple-security-ssl' ), $ip, (int) ceil( $duration / 60 ) ),
				array(
					'ip'      => $ip,
					'strikes' => $strikes,
				),
				'warning'
			);
		}

		$data    = array(
			'ip'            => $ip,
			'fails'         => $fails,
			'first_fail'    => $first,
			'last_fail'     => $now,
			'blocked_until' => $blocked_until,
			'strikes'       => $strikes,
		);
		$formats = array( '%s', '%d', '%d', '%d', '%d', '%d' );
		if ( $row ) {
			$wpdb->update( self::table(), $data, array( 'ip' => $ip ), $formats, array( '%s' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table interne.
		} else {
			$wpdb->insert( self::table(), $data, $formats ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table interne.
		}
	}

	/**
	 * Connexion réussie : les échecs de l'IP repartent de zéro (les récidives sont conservées).
	 *
	 * @return void
	 */
	public function record_success() {
		global $wpdb;
		$ip = self::client_ip();
		if ( '' === $ip || ! self::row( $ip ) ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table interne.
		$wpdb->update(
			self::table(),
			array(
				'fails'      => 0,
				'first_fail' => 0,
			),
			array( 'ip' => $ip ),
			array( '%d', '%d' ),
			array( '%s' )
		); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table interne.
	}

	/**
	 * IP actuellement bloquées.
	 *
	 * @return array[]
	 */
	public static function blocked_list() {
		global $wpdb;
		$table = self::table();
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT ip, blocked_until, strikes FROM {$table} WHERE blocked_until > %d ORDER BY blocked_until DESC LIMIT 200", time() ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Table interne.
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Lève le blocage d'une IP (les récidives sont conservées).
	 *
	 * @param string $ip Adresse normalisée.
	 * @return void
	 */
	public static function unblock( $ip ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table interne.
		$wpdb->update(
			self::table(),
			array(
				'blocked_until' => 0,
				'fails'         => 0,
				'first_fail'    => 0,
			),
			array( 'ip' => $ip ),
			array( '%d', '%d', '%d' ),
			array( '%s' )
		); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table interne.
	}

	/**
	 * Purge quotidienne : lignes sans blocage en cours et inactives depuis 48 h.
	 *
	 * @return void
	 */
	public static function purge() {
		global $wpdb;
		$table = self::table();
		$now   = time();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE blocked_until < %d AND last_fail < %d", $now, $now - self::IDLE_PURGE ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Table interne.
	}

	/**
	 * Adresse de déblocage (nonce propre à l'IP).
	 *
	 * @param string $ip Adresse.
	 * @return string
	 */
	public static function unblock_url( $ip ) {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => self::UNBLOCK_ACT,
					'ip'     => rawurlencode( $ip ),
				),
				admin_url( 'admin-post.php' )
			),
			self::UNBLOCK_ACT . '_' . $ip
		);
	}

	/**
	 * Action « Débloquer ».
	 *
	 * @return void
	 */
	public function action_unblock() {
		$ip = isset( $_GET['ip'] ) ? self::normalize_ip( rawurldecode( sanitize_text_field( wp_unslash( $_GET['ip'] ) ) ) ) : '';
		check_admin_referer( self::UNBLOCK_ACT . '_' . $ip );
		if ( '' === $ip || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Accès refusé.', 'graphin-simple-security-ssl' ), '', array( 'response' => 403 ) );
		}
		self::unblock( $ip );
		Logger::log( 'login_unblocked', /* translators: %s: adresse IP */ sprintf( __( 'IP débloquée : %s.', 'graphin-simple-security-ssl' ), $ip ), array( 'ip' => $ip ) );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => 'gsss-login',
					'gsss_notice' => 'unblocked',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Extensions actives qui limitent déjà les connexions.
	 *
	 * @return string[]
	 */
	public static function conflicting_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$found = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( ! is_plugin_active( $file ) ) {
				continue;
			}
			foreach ( self::$other_limiters as $name ) {
				if ( false !== stripos( $data['Name'], $name ) ) {
					$found[] = $data['Name'];
					break;
				}
			}
		}
		return $found;
	}
}
