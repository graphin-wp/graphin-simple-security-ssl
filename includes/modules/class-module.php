<?php
/**
 * Classe abstraite des modules.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Modules;

defined( 'ABSPATH' ) || exit;

/**
 * Un module = un thème de sécurité, avec ses règles Apache et PHP/Nginx.
 */
abstract class Module {

	/**
	 * Identifiant court, utilisé pour les clés de réglages.
	 *
	 * @return string
	 */
	abstract public function id();

	/**
	 * Le module agit-il ? Faux tant que rien n'est coché.
	 *
	 * @return bool
	 */
	abstract public function is_enabled();

	/**
	 * Hooks PHP (version qui fonctionne sans .htaccess).
	 *
	 * @return void
	 */
	abstract public function register_hooks();

	/**
	 * Lignes à écrire dans .htaccess (mode Apache). Vide par défaut.
	 *
	 * @return string[]
	 */
	public function htaccess_rules() {
		return array();
	}

	/**
	 * Lignes à écrire dans le .htaccess du dossier uploads (mode Apache). Vide par défaut.
	 *
	 * @return string[]
	 */
	public function uploads_htaccess_rules() {
		return array();
	}

	/**
	 * Réglages cochés par « Appliquer les réglages recommandés » (clé => libellé). Ils comptent dans le score.
	 *
	 * @return array
	 */
	public function recommended() {
		return array();
	}

	/**
	 * Snippet Nginx à copier pour les règles impossibles en PHP. Vide par défaut.
	 *
	 * @return string
	 */
	public function nginx_rules() {
		return '';
	}
}
