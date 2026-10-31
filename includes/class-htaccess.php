<?php
/**
 * Écriture sécurisée dans .htaccess : sauvegarde, bloc entre marqueurs, test HTTP, rollback.
 *
 * Le bloc est placé en tête du fichier : une redirection écrite après le bloc WordPress
 * ne s'exécuterait jamais, car la réécriture vers index.php s'arrête avant.
 *
 * Fonctions de fichier natives volontaires : l'écriture doit être atomique (fichier
 * temporaire puis rename) et ne doit pas dépendre des identifiants FTP de WP_Filesystem.
 *
 * @package Graphin\SimpleSecurity
 */

// phpcs:disable WordPress.WP.AlternativeFunctions

namespace Graphin\SimpleSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Gestion du bloc Graph'in dans .htaccess.
 */
class Htaccess {

	const MARKER = 'Graphin Simple Security';

	/**
	 * Chemin du .htaccess principal.
	 *
	 * @return string
	 */
	public static function path() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		return get_home_path() . '.htaccess';
	}

	/**
	 * Le fichier peut-il être écrit (ou créé s'il n'existe pas) ?
	 *
	 * @param string $file Chemin, .htaccess principal par défaut.
	 * @return bool
	 */
	public static function is_writable( $file = '' ) {
		$file = '' === $file ? self::path() : $file;
		return file_exists( $file ) ? is_writable( $file ) : is_writable( dirname( $file ) );
	}

	/**
	 * Texte du bloc, terminé par un saut de ligne.
	 *
	 * @param string[] $lines Règles.
	 * @return string
	 */
	public static function build_block( $lines ) {
		return '# BEGIN ' . self::MARKER . "\n" . implode( "\n", $lines ) . "\n# END " . self::MARKER . "\n";
	}

	/**
	 * Retire le bloc d'un contenu.
	 *
	 * @param string $content Contenu du fichier.
	 * @return string
	 */
	public static function strip_block( $content ) {
		$marker = preg_quote( self::MARKER, '/' );
		$result = preg_replace( '/^# BEGIN ' . $marker . '\R.*?^# END ' . $marker . '(?:\R|$)/ms', '', $content );
		return null === $result ? $content : $result;
	}

	/**
	 * Le contenu porte-t-il notre bloc ?
	 *
	 * @param string $content Contenu.
	 * @return bool
	 */
	public static function has_block( $content ) {
		return false !== strpos( $content, '# BEGIN ' . self::MARKER );
	}

	/**
	 * Chemin du .htaccess du dossier uploads, ou chaîne vide si le dossier est inconnu.
	 *
	 * @return string
	 */
	public static function uploads_path() {
		$uploads = wp_get_upload_dir();
		return empty( $uploads['basedir'] ) ? '' : $uploads['basedir'] . '/.htaccess';
	}

	/**
	 * Règles de tous les modules actifs, en mode Apache seulement.
	 *
	 * @param string $method Méthode du module à appeler : htaccess_rules ou uploads_htaccess_rules.
	 * @return string[]
	 */
	private static function gather( $method ) {
		$lines = array();
		if ( 'apache' === Settings::get( 'server_mode' ) ) {
			foreach ( Plugin::instance()->modules() as $module ) {
				$rules = $module->is_enabled() ? $module->$method() : array();
				if ( ! empty( $rules ) ) {
					$lines[] = '# ' . $module->id();
					$lines   = array_merge( $lines, $rules );
				}
			}
		}
		return $lines;
	}

	/**
	 * Règles du .htaccess principal.
	 *
	 * @return string[]
	 */
	public static function collect_rules() {
		/**
		 * Règles supplémentaires pour le .htaccess principal.
		 *
		 * @param string[] $lines Lignes.
		 */
		return array_values( apply_filters( 'gsss_htaccess_rules', self::gather( 'htaccess_rules' ) ) );
	}

	/**
	 * Règles du .htaccess du dossier uploads.
	 *
	 * @return string[]
	 */
	public static function collect_uploads_rules() {
		/**
		 * Règles supplémentaires pour le .htaccess du dossier uploads.
		 *
		 * @param string[] $lines Lignes.
		 */
		return array_values( apply_filters( 'gsss_uploads_htaccess_rules', self::gather( 'uploads_htaccess_rules' ) ) );
	}

	/**
	 * Aligne le .htaccess principal et celui d'uploads sur les règles des modules actifs.
	 *
	 * @return true|\WP_Error
	 */
	public static function sync() {
		$result = self::apply( self::path(), self::collect_rules() );
		if ( is_wp_error( $result ) ) {
			// Règles non écrites ou restaurées : les modules passent en PHP.
			update_option( 'gsss_htaccess_active', 0, true );
			return $result;
		}
		$uploads = self::uploads_path();
		$lines   = self::collect_uploads_rules();
		if ( '' !== $uploads && is_dir( dirname( $uploads ) ) && ( ! empty( $lines ) || file_exists( $uploads ) ) ) {
			return self::apply( $uploads, $lines );
		}
		return true;
	}

	/**
	 * Le résultat est-il une restauration (les règles cassaient le site) ?
	 *
	 * @param mixed $result Résultat de sync().
	 * @return bool
	 */
	public static function is_rollback( $result ) {
		return is_wp_error( $result ) && 'gsss_htaccess_rollback' === $result->get_error_code();
	}

	/**
	 * Aligne .htaccess ; si les nouvelles règles cassent le site, appelle $restore puis réaligne.
	 *
	 * @param callable $restore Remet les réglages d'avant.
	 * @return true|\WP_Error
	 */
	public static function sync_or_restore( $restore ) {
		$result = self::sync();
		if ( self::is_rollback( $result ) ) {
			call_user_func( $restore );
			self::sync();
		}
		return $result;
	}

	/**
	 * Les règles .htaccess sont-elles en place (mode Apache, dernière écriture réussie) ?
	 *
	 * @return bool
	 */
	public static function rules_served() {
		return 'apache' === Settings::get( 'server_mode' ) && (int) get_option( 'gsss_htaccess_active' );
	}

	/**
	 * Une règle passe-t-elle par PHP ? Oui hors Apache, si .htaccess n'a pas été écrit, ou si le test
	 * d'envoi a montré qu'Apache ne la sert pas (drapeau $flag).
	 *
	 * @param string $flag Option posée par le test d'envoi.
	 * @return bool
	 */
	public static function served_by_php( $flag ) {
		return ! self::rules_served() || (int) get_option( $flag );
	}

	/**
	 * Retire le bloc, sans test HTTP : retirer des règles ne doit jamais être bloqué.
	 *
	 * @return true|\WP_Error
	 */
	public static function remove_all() {
		$result = true;
		foreach ( array( self::path(), self::uploads_path() ) as $file ) {
			if ( '' !== $file && file_exists( $file ) ) {
				$outcome = self::apply( $file, array(), false );
				if ( is_wp_error( $outcome ) ) {
					$result = $outcome;
				}
			}
		}
		return $result;
	}

	/**
	 * Mode secours : retire le bloc s'il est présent, sans toucher aux réglages.
	 *
	 * @return void
	 */
	public static function remove_if_present() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		foreach ( array( self::path(), self::uploads_path() ) as $file ) {
			if ( '' !== $file && file_exists( $file ) && is_readable( $file ) && self::has_block( (string) file_get_contents( $file ) ) ) {
				self::apply( $file, array(), false );
			}
		}
	}

	/**
	 * Écrit le bloc (ou le retire si $lines est vide).
	 *
	 * @param string   $file  Fichier cible.
	 * @param string[] $lines Règles.
	 * @param bool     $test  Tester l'accueil avant et après l'écriture.
	 * @return true|\WP_Error
	 */
	public static function apply( $file, $lines, $test = true ) {
		$existed  = file_exists( $file );
		$original = $existed ? file_get_contents( $file ) : '';
		if ( false === $original ) {
			return new \WP_Error( 'gsss_htaccess_unreadable', __( 'Le fichier .htaccess est illisible.', 'graphin-simple-security-ssl' ) );
		}

		$stripped = self::strip_block( $original );
		$new      = empty( $lines ) ? $stripped : self::build_block( $lines ) . $stripped;
		if ( $new === $original ) {
			self::remember( $file, $new );
			return true;
		}
		if ( ! self::is_writable( $file ) ) {
			return new \WP_Error( 'gsss_htaccess_not_writable', __( 'Le fichier .htaccess n\'est pas inscriptible.', 'graphin-simple-security-ssl' ) );
		}

		$probe = ( $test && ! empty( $lines ) );
		if ( $probe ) {
			$baseline = self::probe();
			if ( is_wp_error( $baseline ) ) {
				$error = new \WP_Error( 'gsss_htaccess_baseline', __( 'Le site ne répond pas correctement avant l\'écriture (ou ne peut pas se tester lui-même) : .htaccess non modifié.', 'graphin-simple-security-ssl' ) );
				self::log( 'htaccess_refused', $error->get_error_message(), array( 'detail' => $baseline->get_error_message() ), 'error' );
				return $error;
			}
		}

		if ( $existed && false === copy( $file, $file . '.gsss-backup' ) ) {
			return new \WP_Error( 'gsss_htaccess_backup', __( 'Sauvegarde de .htaccess impossible : fichier non modifié.', 'graphin-simple-security-ssl' ) );
		}
		if ( ! self::write( $file, $new ) ) {
			return new \WP_Error( 'gsss_htaccess_write', __( 'Écriture de .htaccess impossible.', 'graphin-simple-security-ssl' ) );
		}

		if ( $probe ) {
			$after = self::probe();
			if ( is_wp_error( $after ) ) {
				if ( $existed ) {
					self::write( $file, $original );
				} else {
					wp_delete_file( $file );
				}
				$error = new \WP_Error( 'gsss_htaccess_rollback', __( 'Le site ne répond plus après l\'écriture : .htaccess restauré.', 'graphin-simple-security-ssl' ) );
				self::log( 'htaccess_rollback', $error->get_error_message(), array( 'detail' => $after->get_error_message() ), 'error' );
				return $error;
			}
		}

		if ( '' === $new ) {
			wp_delete_file( $file );
		}
		self::remember( $file, $new );
		self::log( empty( $lines ) ? 'htaccess_removed' : 'htaccess_written', empty( $lines ) ? 'Bloc .htaccess retiré.' : 'Bloc .htaccess écrit.' );
		return true;
	}

	/**
	 * Requête sur la page d'accueil : échec si erreur de transport ou code 5xx.
	 *
	 * @return true|\WP_Error
	 */
	public static function probe() {
		$response = wp_remote_get(
			add_query_arg( 'gsss_probe', (string) time(), home_url( '/' ) ),
			array(
				'timeout'     => 10,
				'redirection' => 5,
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code >= 500 || 0 === $code ) {
			/* translators: %d: code HTTP */
			return new \WP_Error( 'gsss_probe_http', sprintf( __( 'Code HTTP %d.', 'graphin-simple-security-ssl' ), $code ) );
		}
		return true;
	}

	/**
	 * Mémorise si le bloc est dans le .htaccess principal, quel que soit le chemin d'écriture
	 * (enregistrement, désactivation, mode secours) : les modules passent en PHP quand il n'y est pas.
	 *
	 * @param string $file    Fichier écrit.
	 * @param string $content Contenu en place.
	 * @return void
	 */
	private static function remember( $file, $content ) {
		if ( self::path() === $file ) {
			update_option( 'gsss_htaccess_active', self::has_block( $content ) ? 1 : 0, true );
		}
	}

	/**
	 * Écriture atomique : fichier temporaire puis rename, droits conservés.
	 *
	 * @param string $file    Cible.
	 * @param string $content Contenu.
	 * @return bool
	 */
	private static function write( $file, $content ) {
		$tmp = $file . '.gsss-tmp';
		if ( false === file_put_contents( $tmp, $content, LOCK_EX ) ) {
			return false;
		}
		if ( file_exists( $file ) ) {
			chmod( $tmp, fileperms( $file ) & 0777 );
		}
		if ( ! rename( $tmp, $file ) ) {
			wp_delete_file( $tmp );
			return false !== file_put_contents( $file, $content, LOCK_EX );
		}
		return true;
	}

	/**
	 * Ligne de journal, si le journal est chargé (il ne l'est pas en mode secours).
	 *
	 * @param string $event   Code.
	 * @param string $message Texte.
	 * @param array  $context Contexte.
	 * @param string $level   Niveau.
	 * @return void
	 */
	private static function log( $event, $message, $context = array(), $level = 'info' ) {
		if ( class_exists( __NAMESPACE__ . '\Logger' ) && ! ( defined( 'GSSS_SAFE_MODE' ) && GSSS_SAFE_MODE ) ) {
			Logger::log( $event, $message, $context, $level );
		}
	}
}
