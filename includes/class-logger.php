<?php
/**
 * Journal des événements (table gsss_log, 200 lignes maximum).
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Journal.
 */
class Logger {

	const MAX_ROWS   = 200;
	const DB_VERSION = '1';

	/**
	 * Nom complet de la table.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'gsss_log';
	}

	/**
	 * Crée ou met à jour la table.
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
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at datetime NOT NULL,
				level varchar(10) NOT NULL DEFAULT 'info',
				event varchar(60) NOT NULL,
				message text NOT NULL,
				context longtext NULL,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id)
			) {$charset};"
		);
		update_option( 'gsss_db_version', self::DB_VERSION, false );
	}

	/**
	 * Met la table à niveau si le schéma a changé.
	 *
	 * @return void
	 */
	public static function maybe_upgrade() {
		if ( get_option( 'gsss_db_version' ) !== self::DB_VERSION ) {
			self::install();
		}
	}

	/**
	 * Ajoute une ligne puis purge au-delà de 200 lignes.
	 *
	 * @param string $event   Code court (ex. htaccess_written).
	 * @param string $message Texte lisible.
	 * @param array  $context Données complémentaires.
	 * @param string $level   info, warning ou error.
	 * @return void
	 */
	public static function log( $event, $message = '', $context = array(), $level = 'info' ) {
		global $wpdb;
		if ( ! in_array( $level, array( 'info', 'warning', 'error' ), true ) ) {
			$level = 'info';
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table interne du plugin.
		$wpdb->insert(
			self::table(),
			array(
				'created_at' => current_time( 'mysql', true ),
				'level'      => $level,
				'event'      => substr( sanitize_key( $event ), 0, 60 ),
				'message'    => sanitize_text_field( $message ),
				'context'    => empty( $context ) ? null : wp_json_encode( $context ),
				'user_id'    => get_current_user_id(),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d' )
		);
		self::purge();
	}

	/**
	 * Supprime les lignes au-delà des 200 dernières.
	 *
	 * @return void
	 */
	private static function purge() {
		global $wpdb;
		$table  = self::table();
		$cutoff = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} ORDER BY id DESC LIMIT 1 OFFSET %d", self::MAX_ROWS ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Nom de table interne.
		if ( $cutoff ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id <= %d", (int) $cutoff ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Nom de table interne.
		}
	}

	/**
	 * Dernières lignes, la plus récente d'abord.
	 *
	 * @param int $limit Nombre de lignes.
	 * @return array
	 */
	public static function get_recent( $limit = 200 ) {
		global $wpdb;
		$table = self::table();
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", absint( $limit ) ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- Nom de table interne.
		return is_array( $rows ) ? $rows : array();
	}
}
