<?php
/**
 * Alertes par email : agence, et client si la case est cochée.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Envoi des alertes via wp_mail().
 */
class Mailer {

	/**
	 * Destinataires valides, sans doublon.
	 *
	 * @return string[]
	 */
	public static function recipients() {
		$to     = array();
		$agency = Settings::get( 'agency_email', GSSS_AGENCY_EMAIL );
		if ( is_email( $agency ) ) {
			$to[] = $agency;
		}
		if ( Settings::get( 'alert_client' ) ) {
			$client = Settings::get( 'client_email' );
			if ( is_email( $client ) ) {
				$to[] = $client;
			}
		}
		return array_values( array_unique( $to ) );
	}

	/**
	 * Envoie une alerte.
	 *
	 * @param string $subject     Sujet court.
	 * @param string $body        Corps en texte brut.
	 * @param string $dedupe_key  Si renseignée, la même alerte n'est pas renvoyée avant $ttl.
	 * @param int    $ttl         Durée de l'anti-doublon en secondes.
	 * @return bool
	 */
	public static function send( $subject, $body, $dedupe_key = '', $ttl = DAY_IN_SECONDS ) {
		$transient = '';
		if ( '' !== $dedupe_key ) {
			$transient = 'gsss_mail_' . md5( $dedupe_key );
			if ( false !== get_transient( $transient ) ) {
				return false;
			}
		}

		$to = self::recipients();
		if ( empty( $to ) ) {
			Logger::log( 'alert_failed', __( 'Aucun destinataire valide pour l\'alerte.', 'graphin-simple-security-ssl' ), array(), 'error' );
			return false;
		}

		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$subject = sanitize_text_field( '[Graph\'in Security] ' . $site . ' : ' . $subject );
		$body   .= "\n\n--\n" . home_url( '/' );

		$sent = wp_mail( $to, $subject, $body );
		if ( $sent ) {
			if ( '' !== $transient ) {
				set_transient( $transient, 1, $ttl );
			}
			Logger::log( 'alert_sent', $subject, array( 'to' => $to ) );
		} else {
			Logger::log( 'alert_failed', $subject, array( 'to' => $to ), 'error' );
		}
		return (bool) $sent;
	}

	/**
	 * Email de test, sans anti-doublon.
	 *
	 * @return bool
	 */
	public static function send_test() {
		return self::send(
			__( 'Email de test', 'graphin-simple-security-ssl' ),
			__( 'Si vous lisez ce message, les alertes de sécurité arrivent bien à cette adresse.', 'graphin-simple-security-ssl' )
		);
	}
}
