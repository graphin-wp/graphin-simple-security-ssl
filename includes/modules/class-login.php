<?php
/**
 * Module Connexion : double authentification (puis limitation des tentatives et URL personnalisée).
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Modules;

use Graphin\SimpleSecurity\Login\LoginLimiter;
use Graphin\SimpleSecurity\Login\LoginUrl;
use Graphin\SimpleSecurity\Login\Twofactor;
use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Sécurisation de la connexion.
 */
class Login extends Module {

	/**
	 * Déclare les valeurs par défaut, même quand le module est inactif.
	 */
	public function __construct() {
		add_filter( 'gsss_default_settings', array( $this, 'defaults' ) );
	}

	/**
	 * Valeurs par défaut : rien n'agit tant qu'une case n'est pas cochée.
	 *
	 * @param array $defaults Valeurs existantes.
	 * @return array
	 */
	public function defaults( $defaults ) {
		return array_merge(
			$defaults,
			array(
				'login_2fa_enabled'    => 0,
				'login_2fa_enforce'    => 0,
				'login_2fa_grace'      => 7,
				'login_2fa_remember'   => 0,
				'login_limit_enabled'  => 0,
				'login_limit_attempts' => 5,
				'login_limit_window'   => 15,
				'login_limit_block'    => 30,
				'login_proxy'          => 0,
				'login_whitelist'      => array(),
				'login_url_enabled'    => 0,
				'login_url_slug'       => '',
			)
		);
	}

	/**
	 * Identifiant.
	 *
	 * @return string
	 */
	public function id() {
		return 'login';
	}

	/**
	 * Actif si un des blocs est coché.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) Settings::get( 'login_2fa_enabled' ) || (bool) Settings::get( 'login_limit_enabled' ) || (bool) Settings::get( 'login_url_enabled' );
	}

	/**
	 * Hooks des blocs actifs.
	 *
	 * @return void
	 */
	public function register_hooks() {
		if ( Settings::get( 'login_2fa_enabled' ) ) {
			( new Twofactor() )->register_hooks();
		}
		if ( Settings::get( 'login_limit_enabled' ) ) {
			( new LoginLimiter() )->register_hooks();
		}
		if ( Settings::get( 'login_url_enabled' ) ) {
			( new LoginUrl() )->register_hooks();
		}
	}
}
