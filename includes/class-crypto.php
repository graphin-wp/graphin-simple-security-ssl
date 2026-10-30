<?php
/**
 * Chiffrement AES-256-GCM, clé dérivée des salts WordPress.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Chiffrement des secrets stockés en base (secrets TOTP).
 */
class Crypto {

	const CIPHER = 'aes-256-gcm';
	const PREFIX = 'v1:';

	/**
	 * Vérifie que openssl et AES-256-GCM sont disponibles.
	 *
	 * @return bool
	 */
	public static function available() {
		return function_exists( 'openssl_encrypt' ) && in_array( self::CIPHER, openssl_get_cipher_methods(), true );
	}

	/**
	 * Clé de 32 octets dérivée des salts. Si les salts changent, les données deviennent illisibles.
	 *
	 * @return string
	 */
	private static function key() {
		return hash_hmac( 'sha256', 'gsss-crypto-v1', wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), true );
	}

	/**
	 * Chiffre un texte.
	 *
	 * @param string $plain Texte clair.
	 * @return string|false Charge utile, ou false en cas d'échec.
	 */
	public static function encrypt( $plain ) {
		if ( ! self::available() ) {
			return false;
		}
		$iv  = random_bytes( 12 );
		$tag = '';
		$ct  = openssl_encrypt( (string) $plain, self::CIPHER, self::key(), OPENSSL_RAW_DATA, $iv, $tag, '', 16 );
		if ( false === $ct ) {
			return false;
		}
		return self::PREFIX . base64_encode( $iv . $tag . $ct ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Codage binaire, pas d'obscurcissement.
	}

	/**
	 * Déchiffre une charge utile.
	 *
	 * @param string $payload Valeur produite par encrypt().
	 * @return string|false Texte clair, ou false si la valeur est altérée ou illisible.
	 */
	public static function decrypt( $payload ) {
		if ( ! self::available() || ! is_string( $payload ) || 0 !== strpos( $payload, self::PREFIX ) ) {
			return false;
		}
		$raw = base64_decode( substr( $payload, strlen( self::PREFIX ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Décodage binaire.
		if ( false === $raw || strlen( $raw ) < 29 ) {
			return false;
		}
		return openssl_decrypt( substr( $raw, 28 ), self::CIPHER, self::key(), OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
	}
}
