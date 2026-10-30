<?php
/**
 * Module Vulnérabilités : scan quotidien, alertes, notice, mises à jour automatiques.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Modules;

use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Mailer;
use Graphin\SimpleSecurity\Settings;
use Graphin\SimpleSecurity\VulnScanner;

defined( 'ABSPATH' ) || exit;

/**
 * Détection des vulnérabilités connues (WPVulnerability.net).
 */
class Vulnerabilities extends Module {

	const HOOK_DAILY    = 'gsss_daily_vuln_scan';
	const HOOK_CONTINUE = 'gsss_vuln_scan_continue';
	const HOOK_RETRY    = 'gsss_vuln_scan_retry';

	/**
	 * Délais de relance après un échec : 15 min, 1 h, 24 h.
	 *
	 * @var int[]
	 */
	private static $retry_delays = array( 900, 3600, 86400 );

	/**
	 * Déclare les valeurs par défaut, même quand le module est inactif.
	 */
	public function __construct() {
		add_filter( 'gsss_default_settings', array( $this, 'defaults' ) );
	}

	/**
	 * Valeurs par défaut : rien n'agit tant que la case n'est pas cochée.
	 *
	 * @param array $defaults Valeurs existantes.
	 * @return array
	 */
	public function defaults( $defaults ) {
		return array_merge(
			$defaults,
			array(
				'vuln_enabled'      => 0,
				'vuln_min_severity' => 'medium',
				'vuln_auto_update'  => 0,
				'vuln_flag_closed'  => 0,
			)
		);
	}

	/**
	 * Identifiant.
	 *
	 * @return string
	 */
	public function id() {
		return 'vulnerabilities';
	}

	/**
	 * Actif seulement si la case est cochée.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return (bool) Settings::get( 'vuln_enabled' );
	}

	/**
	 * Hooks du module.
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_action( self::HOOK_DAILY, array( $this, 'cron_scan' ) );
		add_action( self::HOOK_RETRY, array( $this, 'cron_scan' ) );
		add_action( self::HOOK_CONTINUE, array( $this, 'cron_continue' ) );
		add_action( 'gsss_vuln_scan_complete', array( $this, 'on_scan_complete' ), 10, 2 );
		add_action( 'admin_notices', array( $this, 'admin_notice' ) );
		if ( Settings::get( 'vuln_auto_update' ) ) {
			add_filter( 'auto_update_plugin', array( $this, 'maybe_auto_update' ), 10, 2 );
		}
		if ( ! wp_next_scheduled( self::HOOK_DAILY ) ) {
			wp_schedule_event( time() + 300, 'daily', self::HOOK_DAILY );
		}
	}

	/**
	 * Planifie ou retire le scan quotidien selon la case.
	 *
	 * @param bool $enabled Module activé.
	 * @return void
	 */
	public static function sync_schedule( $enabled ) {
		if ( $enabled ) {
			if ( ! wp_next_scheduled( self::HOOK_DAILY ) ) {
				wp_schedule_event( time() + 300, 'daily', self::HOOK_DAILY );
			}
			return;
		}
		self::clear_schedule();
	}

	/**
	 * Retire toutes les planifications et un éventuel scan en cours.
	 *
	 * @return void
	 */
	public static function clear_schedule() {
		wp_clear_scheduled_hook( self::HOOK_DAILY );
		wp_clear_scheduled_hook( self::HOOK_CONTINUE );
		wp_clear_scheduled_hook( self::HOOK_RETRY );
		VulnScanner::reset();
	}

	/**
	 * Scan quotidien ou relance : repart de zéro.
	 *
	 * @return void
	 */
	public function cron_scan() {
		VulnScanner::reset();
		$this->run_batch();
	}

	/**
	 * Lot suivant d'un scan en cours.
	 *
	 * @return void
	 */
	public function cron_continue() {
		$this->run_batch();
	}

	/**
	 * Traite un lot et planifie le suivant si besoin.
	 *
	 * @return void
	 */
	private function run_batch() {
		$result = VulnScanner::step();
		if ( empty( $result['done'] ) ) {
			wp_schedule_single_event( time() + 60, self::HOOK_CONTINUE );
		}
	}

	/**
	 * Fin de scan : alerte sur les failles nouvelles, relance en cas d'échec.
	 *
	 * @param array $findings   Failles trouvées.
	 * @param bool  $had_errors Un composant n'a pas pu être interrogé.
	 * @return void
	 */
	public function on_scan_complete( $findings, $had_errors ) {
		$known = get_option( 'gsss_vuln_known', array() );
		$known = is_array( $known ) ? $known : array();
		$ids   = array();
		$new   = array();
		foreach ( $findings as $finding ) {
			$ids[] = $finding['id'];
			if ( ! in_array( $finding['id'], $known, true ) ) {
				$new[] = $finding;
			}
		}
		update_option( 'gsss_vuln_known', $ids, false );

		/* translators: 1: nombre de failles, 2: nombre d'erreurs */
		Logger::log( 'vuln_scan', sprintf( __( 'Scan terminé : %1$d faille(s), %2$d composant(s) non analysé(s).', 'graphin-simple-security-ssl' ), count( $findings ), $had_errors ? (int) VulnScanner::results()['errors'] : 0 ), array( 'new' => count( $new ) ) );

		$threshold = VulnScanner::rank( (string) Settings::get( 'vuln_min_severity', 'medium' ) );
		$to_alert  = array();
		foreach ( $new as $finding ) {
			if ( VulnScanner::rank( $finding['severity'] ) >= $threshold ) {
				$to_alert[] = $finding;
			}
		}
		if ( ! empty( $to_alert ) ) {
			$this->send_alert( $to_alert );
		}

		$this->schedule_retry( $had_errors );
	}

	/**
	 * Un seul email groupé pour les failles nouvelles.
	 *
	 * @param array $findings Failles à signaler.
	 * @return void
	 */
	private function send_alert( $findings ) {
		$lines = array();
		$ids   = array();
		foreach ( $findings as $finding ) {
			$ids[]   = $finding['id'];
			$line    = '- [' . VulnScanner::label( $finding['severity'] ) . '] ' . $finding['name'] . ' ' . $finding['version'] . ' : ' . $finding['description'];
			$line   .= '' !== $finding['fixed'] ? ' (corrigé en ' . $finding['fixed'] . ')' : ' (pas de correctif connu)';
			$line   .= '' !== $finding['link'] ? "\n  " . $finding['link'] : '';
			$lines[] = $line;
		}
		/* translators: %d: nombre de failles */
		$subject = sprintf( _n( '%d nouvelle faille détectée', '%d nouvelles failles détectées', count( $findings ), 'graphin-simple-security-ssl' ), count( $findings ) );
		$body    = $subject . " :\n\n" . implode( "\n", $lines ) . "\n\n" . admin_url( 'admin.php?page=gsss-vulns' );
		Mailer::send( $subject, $body, 'vuln:' . md5( implode( ',', $ids ) ) );
	}

	/**
	 * Relance progressive après un échec : 15 min, 1 h, puis 24 h.
	 *
	 * @param bool $had_errors Échec partiel ou total.
	 * @return void
	 */
	private function schedule_retry( $had_errors ) {
		if ( ! $had_errors ) {
			update_option( 'gsss_vuln_retry', 0, false );
			return;
		}
		$attempt = (int) get_option( 'gsss_vuln_retry', 0 );
		if ( $attempt >= count( self::$retry_delays ) ) {
			update_option( 'gsss_vuln_retry', 0, false );
			return;
		}
		wp_schedule_single_event( time() + self::$retry_delays[ $attempt ], self::HOOK_RETRY );
		update_option( 'gsss_vuln_retry', $attempt + 1, false );
	}

	/**
	 * Notice rouge sur le tableau de bord WordPress.
	 *
	 * @return void
	 */
	public function admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( ! $screen || 'dashboard' !== $screen->id ) {
			return;
		}
		$results = VulnScanner::results();
		$serious = 0;
		foreach ( $results['findings'] as $finding ) {
			if ( VulnScanner::rank( $finding['severity'] ) >= VulnScanner::rank( 'high' ) ) {
				++$serious;
			}
		}
		$url = admin_url( 'admin.php?page=gsss-vulns' );
		if ( $serious > 0 ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Graph\'in Security :', 'graphin-simple-security-ssl' ) . '</strong> ';
			/* translators: %d: nombre de failles */
			echo esc_html( sprintf( _n( '%d faille critique ou élevée sur ce site.', '%d failles critiques ou élevées sur ce site.', $serious, 'graphin-simple-security-ssl' ), $serious ) );
			echo ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Voir le détail', 'graphin-simple-security-ssl' ) . '</a></p></div>';
		}
		if ( Settings::get( 'vuln_flag_closed' ) && ! empty( $results['closed'] ) ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Graph\'in Security :', 'graphin-simple-security-ssl' ) . '</strong> ';
			/* translators: %d: nombre d'extensions */
			echo esc_html( sprintf( _n( '%d extension installée est fermée sur wordpress.org (abandonnée ou retirée).', '%d extensions installées sont fermées sur wordpress.org (abandonnées ou retirées).', count( $results['closed'] ), 'graphin-simple-security-ssl' ), count( $results['closed'] ) ) );
			echo ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Voir le détail', 'graphin-simple-security-ssl' ) . '</a></p></div>';
		}
	}

	/**
	 * Autorise la mise à jour automatique d'un plugin vulnérable si wordpress.org propose
	 * une version au moins égale à la version corrigée.
	 *
	 * @param bool|null $update Décision actuelle.
	 * @param object    $item   Mise à jour proposée.
	 * @return bool|null
	 */
	public function maybe_auto_update( $update, $item ) {
		if ( $update || ! is_object( $item ) || empty( $item->new_version ) || empty( $item->package ) || false === strpos( (string) $item->package, 'downloads.wordpress.org' ) ) {
			return $update;
		}
		$slugs = array();
		if ( ! empty( $item->slug ) ) {
			$slugs[] = (string) $item->slug;
		}
		if ( ! empty( $item->plugin ) ) {
			$dir     = dirname( (string) $item->plugin );
			$slugs[] = '.' === $dir ? basename( (string) $item->plugin, '.php' ) : $dir;
		}
		foreach ( VulnScanner::results()['findings'] as $finding ) {
			if ( 'plugin' === $finding['type'] && in_array( $finding['slug'], $slugs, true ) && '' !== $finding['fixed'] && version_compare( (string) $item->new_version, $finding['fixed'], '>=' ) ) {
				if ( false === get_transient( 'gsss_autoupd_' . $finding['slug'] ) ) {
					set_transient( 'gsss_autoupd_' . $finding['slug'], 1, DAY_IN_SECONDS );
					/* translators: 1: nom du plugin, 2: version proposée */
					Logger::log( 'vuln_auto_update', sprintf( __( 'Mise à jour automatique autorisée : %1$s vers %2$s.', 'graphin-simple-security-ssl' ), $finding['name'], (string) $item->new_version ) );
				}
				return true;
			}
		}
		return $update;
	}
}
