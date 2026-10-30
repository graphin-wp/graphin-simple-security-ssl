<?php
/**
 * Module Durcissement : 13 mesures, chacune derrière une case.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Modules;

use Graphin\SimpleSecurity\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Mesures de durcissement WordPress et serveur.
 */
class Hardening extends Module {

	/**
	 * Mots interdits comme identifiant à la création d'un compte.
	 *
	 * @var string[]
	 */
	private static $reserved_logins = array( 'admin', 'administrator', 'administrateur' );

	/**
	 * Description des mesures : clé de réglage => libellé, aide, recommandée, Apache seulement, avertissement.
	 *
	 * @return array
	 */
	public static function options() {
		return array(
			'hard_xmlrpc'         => array(
				'label'       => __( 'Désactiver XML-RPC', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Ferme xmlrpc.php, cible fréquente des attaques par force brute. En Apache, le fichier est aussi refusé avant PHP.', 'graphin-simple-security-ssl' ),
				'recommended' => true,
				'apache'      => false,
				'warning'     => __( 'Jetpack et l\'application mobile WordPress utilisent XML-RPC.', 'graphin-simple-security-ssl' ),
			),
			'hard_file_edit'      => array(
				'label'       => __( 'Désactiver l\'éditeur de fichiers de l\'admin', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Retire les éditeurs de thèmes et d\'extensions : un accès administrateur volé ne permet plus de modifier le code depuis l\'admin.', 'graphin-simple-security-ssl' ),
				'recommended' => true,
				'apache'      => false,
				'warning'     => '',
			),
			'hard_enum_users'     => array(
				'label'       => __( 'Bloquer l\'énumération des utilisateurs', 'graphin-simple-security-ssl' ),
				'help'        => __( '?author=N renvoie une erreur 404 aux visiteurs, et la liste des utilisateurs de l\'API REST est réservée aux personnes connectées.', 'graphin-simple-security-ssl' ),
				'recommended' => true,
				'apache'      => false,
				'warning'     => '',
			),
			'hard_hide_version'   => array(
				'label'       => __( 'Masquer la version de WordPress', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Retire la balise generator, la version dans les flux RSS et le paramètre ?ver= des scripts et styles du cœur.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'apache'      => false,
				'warning'     => '',
			),
			'hard_login_errors'   => array(
				'label'       => __( 'Messages d\'erreur de connexion génériques', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Affiche « identifiants incorrects » sans dire si l\'identifiant ou le mot de passe est en cause.', 'graphin-simple-security-ssl' ),
				'recommended' => true,
				'apache'      => false,
				'warning'     => '',
			),
			'hard_uploads_php'    => array(
				'label'       => __( 'Bloquer l\'exécution de PHP dans le dossier uploads', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Un fichier PHP déposé dans les médias ne peut plus être lancé depuis le navigateur.', 'graphin-simple-security-ssl' ),
				'recommended' => true,
				'apache'      => true,
				'warning'     => __( 'Quelques extensions exécutent du PHP depuis ce dossier : testez le site après activation.', 'graphin-simple-security-ssl' ),
			),
			'hard_no_indexes'     => array(
				'label'       => __( 'Désactiver le listing des répertoires', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Un dossier sans page d\'index n\'affiche plus la liste de ses fichiers (Options -Indexes).', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'apache'      => true,
				'warning'     => '',
			),
			'hard_protect_files'  => array(
				'label'       => __( 'Protéger les fichiers sensibles', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Refuse l\'accès direct à wp-config.php, .htaccess, readme.html, license.txt, debug.log et aux sauvegardes du plugin.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'apache'      => true,
				'warning'     => '',
			),
			'hard_app_passwords'  => array(
				'label'       => __( 'Désactiver les mots de passe d\'application', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Supprime la possibilité de créer des accès API par mot de passe d\'application.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'apache'      => false,
				'warning'     => __( 'Vérifiez d\'abord qu\'aucun outil connecté au site n\'en dépend (console, agent, connecteurs).', 'graphin-simple-security-ssl' ),
			),
			'hard_admin_names'    => array(
				'label'       => __( 'Interdire les identifiants admin, administrator et administrateur', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Refuse ces identifiants à la création d\'un compte et signale les comptes existants qui les portent.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'apache'      => false,
				'warning'     => '',
			),
			'hard_pingbacks'      => array(
				'label'       => __( 'Désactiver les pingbacks entrants', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Refuse les pings reçus et retire l\'en-tête X-Pingback. Utile même si XML-RPC reste ouvert.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'apache'      => false,
				'warning'     => '',
			),
			'hard_opcache_notice' => array(
				'label'       => __( 'Masquer le test OPcache de Santé du site', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Sur l\'hébergement mutualisé, OPcache tourne mais son API est restreinte : le test conclut à tort qu\'il est désactivé. Sans effet quand l\'API est accessible.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'apache'      => false,
				'warning'     => '',
			),
			'hard_register_alert' => array(
				'label'       => __( 'Alerter si les inscriptions donnent un rôle autre qu\'Abonné', 'graphin-simple-security-ssl' ),
				'help'        => __( 'Affiche un avertissement quand les inscriptions sont ouvertes avec un rôle par défaut plus puissant qu\'Abonné. Rien n\'est modifié.', 'graphin-simple-security-ssl' ),
				'recommended' => false,
				'apache'      => false,
				'warning'     => '',
			),
		);
	}

	/**
	 * Déclare les valeurs par défaut, même quand le module est inactif.
	 */
	public function __construct() {
		add_filter( 'gsss_default_settings', array( $this, 'defaults' ) );
	}

	/**
	 * Valeurs par défaut : tout est désactivé.
	 *
	 * @param array $defaults Valeurs existantes.
	 * @return array
	 */
	public function defaults( $defaults ) {
		return array_merge( $defaults, array_fill_keys( array_keys( self::options() ), 0 ) );
	}

	/**
	 * Identifiant.
	 *
	 * @return string
	 */
	public function id() {
		return 'hardening';
	}

	/**
	 * Une mesure est-elle cochée ?
	 *
	 * @param string $key Clé de réglage.
	 * @return bool
	 */
	private function on( $key ) {
		return (bool) Settings::get( $key );
	}

	/**
	 * Actif dès qu'une case est cochée.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		foreach ( array_keys( self::options() ) as $key ) {
			if ( $this->on( $key ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Réglages à cocher par « Appliquer les réglages recommandés ».
	 *
	 * @return array
	 */
	public function recommended() {
		$keys = array();
		foreach ( self::options() as $key => $option ) {
			if ( $option['recommended'] ) {
				$keys[ $key ] = 1;
			}
		}
		return $keys;
	}

	/**
	 * Hooks PHP de chaque mesure cochée.
	 *
	 * @return void
	 */
	public function register_hooks() {
		if ( $this->on( 'hard_xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		}
		if ( $this->on( 'hard_file_edit' ) ) {
			// Une constante ne se définit pas par filtre : on la pose au chargement, sans toucher à wp-config.php.
			if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
				define( 'DISALLOW_FILE_EDIT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Constante du cœur WordPress.
			}
			add_filter( 'map_meta_cap', array( $this, 'block_file_edit_caps' ), 10, 2 );
		}
		if ( $this->on( 'hard_enum_users' ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_query' ), 1 );
			add_filter( 'rest_endpoints', array( $this, 'restrict_users_endpoints' ) );
		}
		if ( $this->on( 'hard_hide_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'script_loader_src', array( $this, 'strip_core_version' ), 9999 );
			add_filter( 'style_loader_src', array( $this, 'strip_core_version' ), 9999 );
		}
		if ( $this->on( 'hard_login_errors' ) ) {
			add_filter( 'wp_login_errors', array( $this, 'generic_login_errors' ) );
		}
		if ( $this->on( 'hard_app_passwords' ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}
		if ( $this->on( 'hard_admin_names' ) ) {
			add_filter( 'illegal_user_logins', array( $this, 'reserved_logins' ) );
		}
		if ( $this->on( 'hard_pingbacks' ) ) {
			add_filter( 'xmlrpc_methods', array( $this, 'remove_pingback_methods' ) );
			add_filter( 'pings_open', '__return_false', 99 );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		}
		if ( $this->on( 'hard_opcache_notice' ) ) {
			add_filter( 'site_status_tests', array( $this, 'hide_opcache_test' ) );
		}
		if ( $this->on( 'hard_register_alert' ) ) {
			add_action( 'admin_notices', array( $this, 'registration_notice' ) );
		}
	}

	/**
	 * Retire l'en-tête X-Pingback.
	 *
	 * @param array $headers En-têtes.
	 * @return array
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Retire les méthodes pingback de XML-RPC.
	 *
	 * @param array $methods Méthodes.
	 * @return array
	 */
	public function remove_pingback_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Renfort de DISALLOW_FILE_EDIT si wp-config.php le définit à false.
	 *
	 * @param string[] $caps Capacités requises.
	 * @param string   $cap  Capacité demandée.
	 * @return string[]
	 */
	public function block_file_edit_caps( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_files', 'edit_plugins', 'edit_themes' ), true ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	/**
	 * ?author=N renvoie une 404 aux visiteurs. Les pages d'auteur en URL propre ne sont pas touchées.
	 *
	 * @return void
	 */
	public function block_author_query() {
		if ( is_user_logged_in() || ! isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Lecture seule, aucune action.
			return;
		}
		global $wp_query;
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
		$template = get_query_template( '404' );
		if ( $template ) {
			include $template;
		}
		exit;
	}

	/**
	 * Retire les routes utilisateurs de l'API REST pour les visiteurs.
	 *
	 * @param array $endpoints Routes.
	 * @return array
	 */
	public function restrict_users_endpoints( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/**
	 * Retire ?ver= quand il porte la version de WordPress.
	 *
	 * @param string $src Adresse du script ou du style.
	 * @return string
	 */
	public function strip_core_version( $src ) {
		if ( is_string( $src ) && false !== strpos( $src, 'ver=' . get_bloginfo( 'version' ) ) ) {
			return remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Remplace les erreurs d'identifiant et de mot de passe par un message unique.
	 *
	 * @param \WP_Error $errors Erreurs de la page de connexion.
	 * @return \WP_Error
	 */
	public function generic_login_errors( $errors ) {
		$found = false;
		foreach ( array( 'invalid_username', 'invalid_email', 'incorrect_password' ) as $code ) {
			if ( $errors->get_error_message( $code ) ) {
				$errors->remove( $code );
				$found = true;
			}
		}
		if ( $found ) {
			$errors->add( 'gsss_invalid_login', __( '<strong>Erreur :</strong> identifiants incorrects.', 'graphin-simple-security-ssl' ) );
		}
		return $errors;
	}

	/**
	 * Ajoute les identifiants interdits.
	 *
	 * @param string[] $logins Identifiants déjà interdits.
	 * @return string[]
	 */
	public function reserved_logins( $logins ) {
		return array_merge( (array) $logins, self::$reserved_logins );
	}

	/**
	 * Comptes existants qui portent un identifiant interdit.
	 *
	 * @return string[]
	 */
	public static function flagged_users() {
		$found = array();
		foreach ( self::$reserved_logins as $login ) {
			$user = get_user_by( 'login', $login );
			if ( $user ) {
				$found[] = $user->user_login;
			}
		}
		return $found;
	}

	/**
	 * Masque le test OPcache quand l'API est restreinte (logique de Graph'in Hardening 1.0.3).
	 *
	 * @param array $tests Tests de Santé du site.
	 * @return array
	 */
	public function hide_opcache_test( $tests ) {
		if ( ! ini_get( 'opcache.enable' ) || ! ini_get( 'opcache.restrict_api' ) ) {
			return $tests;
		}
		foreach ( array( 'direct', 'async' ) as $type ) {
			foreach ( array_keys( isset( $tests[ $type ] ) ? $tests[ $type ] : array() ) as $key ) {
				if ( preg_match( '/opcode|opcache/i', (string) $key ) ) {
					unset( $tests[ $type ][ $key ] );
				}
			}
		}
		return $tests;
	}

	/**
	 * Rôle par défaut des inscriptions, si elles sont ouvertes avec autre chose qu'Abonné.
	 *
	 * @return string Nom du rôle, ou chaîne vide.
	 */
	public static function risky_registration_role() {
		$role = (string) get_option( 'default_role' );
		if ( get_option( 'users_can_register' ) && 'subscriber' !== $role ) {
			$names = wp_roles()->role_names;
			return isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : $role;
		}
		return '';
	}

	/**
	 * Alerte sur le tableau de bord et les réglages généraux de WordPress.
	 *
	 * @return void
	 */
	public function registration_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( ! $screen || ! in_array( $screen->id, array( 'dashboard', 'options-general' ), true ) ) {
			return;
		}
		$role = self::risky_registration_role();
		if ( '' === $role ) {
			return;
		}
		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Graph\'in Security :', 'graphin-simple-security-ssl' ) . '</strong> ';
		/* translators: %s: nom du rôle */
		echo esc_html( sprintf( __( 'les inscriptions sont ouvertes et chaque nouveau compte reçoit le rôle « %s ».', 'graphin-simple-security-ssl' ), $role ) );
		echo ' <a href="' . esc_url( admin_url( 'options-general.php' ) ) . '">' . esc_html__( 'Modifier dans Réglages généraux', 'graphin-simple-security-ssl' ) . '</a></p></div>';
	}

	/**
	 * Bloc d'autorisation Apache 2.4 avec repli 2.2.
	 *
	 * @return string[]
	 */
	private static function deny_lines() {
		return array(
			"\t<IfModule mod_authz_core.c>",
			"\t\tRequire all denied",
			"\t</IfModule>",
			"\t<IfModule !mod_authz_core.c>",
			"\t\tOrder deny,allow",
			"\t\tDeny from all",
			"\t</IfModule>",
		);
	}

	/**
	 * Règles du .htaccess principal.
	 *
	 * @return string[]
	 */
	public function htaccess_rules() {
		$lines = array();
		if ( $this->on( 'hard_xmlrpc' ) ) {
			$lines = array_merge( $lines, array( '<Files xmlrpc.php>' ), self::deny_lines(), array( '</Files>' ) );
		}
		if ( $this->on( 'hard_no_indexes' ) ) {
			$lines[] = 'Options -Indexes';
		}
		if ( $this->on( 'hard_protect_files' ) ) {
			$lines = array_merge( $lines, array( '<FilesMatch "^(wp-config\.php|\.ht.*|readme\.html|license\.txt|debug\.log|.*\.gsss-backup)$">' ), self::deny_lines(), array( '</FilesMatch>' ) );
		}
		return $lines;
	}

	/**
	 * Règles du .htaccess d'uploads : aucun script exécutable.
	 *
	 * @return string[]
	 */
	public function uploads_htaccess_rules() {
		if ( ! $this->on( 'hard_uploads_php' ) ) {
			return array();
		}
		return array_merge( array( '<FilesMatch "\.(?i:php|phtml|phps|phar|pht|php[0-9])$">' ), self::deny_lines(), array( '</FilesMatch>' ) );
	}

	/**
	 * Snippet Nginx pour les règles qui n'existent pas en PHP.
	 *
	 * @return string
	 */
	public function nginx_rules() {
		$out = array();
		if ( $this->on( 'hard_xmlrpc' ) ) {
			$out[] = 'location = /xmlrpc.php { deny all; }';
		}
		if ( $this->on( 'hard_uploads_php' ) ) {
			$out[] = 'location ~* ^/wp-content/uploads/.*\.(php|phtml|phps|phar|pht|php[0-9])$ { deny all; }';
		}
		if ( $this->on( 'hard_no_indexes' ) ) {
			$out[] = 'autoindex off;';
		}
		if ( $this->on( 'hard_protect_files' ) ) {
			$out[] = 'location ~* ^/(wp-config\.php|readme\.html|license\.txt|wp-content/debug\.log)$ { deny all; }';
			$out[] = 'location ~ /\.ht { deny all; }';
		}
		return implode( "\n", $out );
	}
}
