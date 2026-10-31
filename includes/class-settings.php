<?php
/**
 * Lecture et écriture des réglages (une seule option, un tableau).
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Réglages du plugin.
 */
class Settings {

	const OPTION = 'gsss_settings';

	/**
	 * Bornes des réglages numériques : clé => array( min, max ).
	 *
	 * @var array
	 */
	private static $ranges = array(
		'login_2fa_grace'      => array( 0, 90 ),
		'login_limit_attempts' => array( 1, 50 ),
		'login_limit_window'   => array( 1, 1440 ),
		'login_limit_block'    => array( 1, 1440 ),
	);

	/**
	 * Valeurs par défaut : tout est désactivé tant que l'utilisateur ne coche rien.
	 *
	 * @return array
	 */
	public static function defaults() {
		$defaults = array(
			'server_mode'  => 'apache',
			'agency_email' => GSSS_AGENCY_EMAIL,
			'alert_client' => 0,
			'client_email' => '',
		);
		/**
		 * Les modules ajoutent leurs valeurs par défaut.
		 *
		 * @param array $defaults Valeurs par défaut.
		 */
		return apply_filters( 'gsss_default_settings', $defaults );
	}

	/**
	 * Tous les réglages, complétés par les valeurs par défaut.
	 *
	 * @return array
	 */
	public static function all() {
		$stored = get_option( self::OPTION, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::defaults(), $stored );
	}

	/**
	 * Lit un réglage.
	 *
	 * @param string $key     Clé.
	 * @param mixed  $fallback Valeur de repli si la clé est inconnue.
	 * @return mixed
	 */
	public static function get( $key, $fallback = null ) {
		$all = self::all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $fallback;
	}

	/**
	 * Écrit un réglage après nettoyage selon le type de la valeur par défaut.
	 *
	 * @param string $key   Clé connue.
	 * @param mixed  $value Valeur.
	 * @return bool False si la clé est inconnue.
	 */
	public static function set( $key, $value ) {
		$defaults = self::defaults();
		if ( ! array_key_exists( $key, $defaults ) ) {
			return false;
		}
		$all         = self::all();
		$all[ $key ] = self::sanitize_value( $key, $value, $defaults[ $key ] );
		return update_option( self::OPTION, $all, false );
	}

	/**
	 * Écrit plusieurs réglages en une seule écriture en base. Les clés inconnues sont ignorées.
	 *
	 * @param array $values Clé => valeur.
	 * @return bool
	 */
	public static function set_many( $values ) {
		$defaults = self::defaults();
		$all      = self::all();
		foreach ( $values as $key => $value ) {
			if ( array_key_exists( $key, $defaults ) ) {
				$all[ $key ] = self::sanitize_value( $key, $value, $defaults[ $key ] );
			}
		}
		return update_option( self::OPTION, $all, false );
	}

	/**
	 * Nettoie une valeur d'après le type attendu.
	 *
	 * @param string $key     Clé.
	 * @param mixed  $value   Valeur reçue.
	 * @param mixed  $fallback Valeur par défaut qui donne le type.
	 * @return mixed
	 */
	private static function sanitize_value( $key, $value, $fallback ) {
		if ( 'server_mode' === $key ) {
			return in_array( $value, array( 'apache', 'other' ), true ) ? $value : 'apache';
		}
		if ( false !== strpos( $key, 'email' ) ) {
			return sanitize_email( (string) $value );
		}
		if ( is_int( $fallback ) ) {
			$value = absint( $value );
			return isset( self::$ranges[ $key ] ) ? max( self::$ranges[ $key ][0], min( self::$ranges[ $key ][1], $value ) ) : $value;
		}
		if ( is_array( $fallback ) ) {
			return is_array( $value ) ? array_map( 'sanitize_text_field', $value ) : array();
		}
		return sanitize_text_field( (string) $value );
	}
}
