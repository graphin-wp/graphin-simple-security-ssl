<?php
/**
 * TOTP (RFC 6238) et HOTP (RFC 4226), sans dépendance.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Mots de passe à usage unique basés sur le temps.
 */
class Totp {

	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	const PERIOD   = 30;
	const DIGITS   = 6;

	/**
	 * Secret aléatoire de 160 bits, en base32.
	 *
	 * @return string
	 */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * Base32 (RFC 4648), sans remplissage.
	 *
	 * @param string $bin Données binaires.
	 * @return string
	 */
	public static function base32_encode( $bin ) {
		$bits = '';
		foreach ( str_split( $bin ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::ALPHABET[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	/**
	 * Décodage base32. Les espaces, tirets et minuscules sont tolérés.
	 *
	 * @param string $b32 Texte base32.
	 * @return string|false
	 */
	public static function base32_decode( $b32 ) {
		$b32 = strtoupper( preg_replace( '/[\s-]+/', '', (string) $b32 ) );
		if ( '' === $b32 || preg_match( '/[^A-Z2-7]/', $b32 ) ) {
			return false;
		}
		$bits = '';
		foreach ( str_split( $b32 ) as $char ) {
			$bits .= str_pad( decbin( strpos( self::ALPHABET, $char ) ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/**
	 * HOTP (RFC 4226), SHA-1.
	 *
	 * @param string $key     Clé binaire.
	 * @param int    $counter Compteur.
	 * @param int    $digits  Nombre de chiffres.
	 * @return string
	 */
	public static function hotp( $key, $counter, $digits = self::DIGITS ) {
		$hash   = hash_hmac( 'sha1', pack( 'J', $counter ), $key, true );
		$offset = ord( $hash[19] ) & 0x0f;
		$value  = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xff );
		return str_pad( (string) ( $value % ( 10 ** $digits ) ), $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * Vérifie un code TOTP, avec une tolérance d'un pas de chaque côté.
	 * Un pas déjà accepté (ou plus ancien) est refusé : pas de rejeu.
	 *
	 * @param string   $secret    Secret base32.
	 * @param string   $code      Code saisi.
	 * @param int      $last_step Dernier pas accepté pour cet utilisateur.
	 * @param int|null $time      Heure de référence (tests).
	 * @param int      $window    Nombre de pas de tolérance.
	 * @return int|false Pas accepté, ou false.
	 */
	public static function verify( $secret, $code, $last_step = 0, $time = null, $window = 1 ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		$key  = self::base32_decode( $secret );
		if ( false === $key || ! preg_match( '/^\d{' . self::DIGITS . '}$/', $code ) ) {
			return false;
		}
		$now = (int) floor( ( null === $time ? time() : $time ) / self::PERIOD );
		for ( $step = $now - $window; $step <= $now + $window; $step++ ) {
			if ( $step > $last_step && hash_equals( self::hotp( $key, $step ), $code ) ) {
				return $step;
			}
		}
		return false;
	}

	/**
	 * Adresse otpauth:// lue par les applications d'authentification.
	 *
	 * @param string $secret Secret base32.
	 * @param string $label  Compte affiché (email ou identifiant).
	 * @param string $issuer Nom du site.
	 * @return string
	 */
	public static function uri( $secret, $label, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $label ) . '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
	}
}
