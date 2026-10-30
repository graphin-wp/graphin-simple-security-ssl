<?php
/**
 * Double authentification : TOTP, code par email, codes de récupération.
 *
 * Le cookie de connexion n'est posé qu'après le second facteur. Seule la page de connexion
 * WordPress peut ouvrir une session pour un compte protégé : les autres portes d'entrée
 * (wp_signon, XML-RPC) refusent le mot de passe seul, sinon la 2FA serait contournable.
 *
 * @package Graphin\SimpleSecurity
 */

namespace Graphin\SimpleSecurity\Login;

use Graphin\SimpleSecurity\Crypto;
use Graphin\SimpleSecurity\Logger;
use Graphin\SimpleSecurity\Settings;
use Graphin\SimpleSecurity\Totp;

defined( 'ABSPATH' ) || exit;

/**
 * Second facteur à la connexion.
 */
class Twofactor {

	const META_SECRET   = 'gsss_2fa_secret';
	const META_ENABLED  = 'gsss_2fa_enabled';
	const META_STEP     = 'gsss_2fa_last_step';
	const META_RECOVERY = 'gsss_2fa_recovery';
	const META_DEVICES  = 'gsss_2fa_devices';
	const META_PENDING  = 'gsss_2fa_pending_secret';

	const TOKEN_TTL     = 600;
	const MAX_TRIES     = 5;
	const EMAIL_TTL     = 600;
	const EMAIL_PAUSE   = 60;
	const DEVICE_COOKIE = 'gsss_2fa_device';
	const DEVICE_DAYS   = 30;
	const DEVICE_MAX    = 5;
	const CODES_COUNT   = 10;
	const PAGE          = 'gsss-2fa';

	/**
	 * Suffixe de la page de configuration, pour charger les assets seulement là.
	 *
	 * @var string
	 */
	private $page_hook = '';

	/**
	 * Branche les hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_filter( 'authenticate', array( $this, 'intercept' ), 100, 3 );
		add_action( 'login_form_gsss_2fa', array( $this, 'handle_challenge' ) );

		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'admin_post_gsss_2fa_begin', array( $this, 'action_begin' ) );
		add_action( 'admin_post_gsss_2fa_cancel', array( $this, 'action_cancel' ) );
		add_action( 'admin_post_gsss_2fa_confirm', array( $this, 'action_confirm' ) );
		add_action( 'admin_post_gsss_2fa_disable', array( $this, 'action_disable' ) );
		add_action( 'admin_post_gsss_2fa_regen', array( $this, 'action_regen' ) );
		add_action( 'admin_post_gsss_2fa_reset', array( $this, 'action_reset' ) );

		add_action( 'admin_init', array( $this, 'enforce_redirect' ) );
		add_action( 'admin_notices', array( $this, 'reminder_notice' ) );
	}

	// État d'un utilisateur.

	/**
	 * L'utilisateur a-t-il activé la 2FA ?
	 *
	 * @param int $user_id Identifiant.
	 * @return bool
	 */
	public static function user_has_2fa( $user_id ) {
		return '1' === (string) get_user_meta( $user_id, self::META_ENABLED, true ) && '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/**
	 * Secret TOTP déchiffré.
	 *
	 * @param int $user_id Identifiant.
	 * @return string|false
	 */
	private static function secret_of( $user_id ) {
		return Crypto::decrypt( (string) get_user_meta( $user_id, self::META_SECRET, true ) );
	}

	/**
	 * Active la 2FA et génère les codes de récupération.
	 *
	 * @param int    $user_id Identifiant.
	 * @param string $secret  Secret base32.
	 * @return string[]|false Codes de récupération en clair (à afficher une seule fois).
	 */
	public static function enable_for_user( $user_id, $secret ) {
		$payload = Crypto::encrypt( $secret );
		if ( false === $payload ) {
			return false;
		}
		update_user_meta( $user_id, self::META_SECRET, $payload );
		update_user_meta( $user_id, self::META_ENABLED, '1' );
		update_user_meta( $user_id, self::META_STEP, 0 );
		delete_user_meta( $user_id, self::META_PENDING );
		delete_user_meta( $user_id, self::META_DEVICES );
		return self::new_recovery_codes( $user_id );
	}

	/**
	 * Retire toute trace de 2FA d'un utilisateur.
	 *
	 * @param int $user_id Identifiant.
	 * @return void
	 */
	public static function disable_for_user( $user_id ) {
		foreach ( array( self::META_SECRET, self::META_ENABLED, self::META_STEP, self::META_RECOVERY, self::META_DEVICES, self::META_PENDING ) as $key ) {
			delete_user_meta( $user_id, $key );
		}
	}

	/**
	 * Génère de nouveaux codes de récupération, stockés hachés.
	 *
	 * @param int $user_id Identifiant.
	 * @return string[] Codes en clair, format xxxxx-xxxxx.
	 */
	public static function new_recovery_codes( $user_id ) {
		$alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
		$plain    = array();
		$hashes   = array();
		for ( $i = 0; $i < self::CODES_COUNT; $i++ ) {
			$raw = '';
			for ( $j = 0; $j < 10; $j++ ) {
				$raw .= $alphabet[ random_int( 0, strlen( $alphabet ) - 1 ) ];
			}
			$plain[]  = substr( $raw, 0, 5 ) . '-' . substr( $raw, 5 );
			$hashes[] = wp_hash_password( $raw );
		}
		update_user_meta( $user_id, self::META_RECOVERY, $hashes );
		return $plain;
	}

	/**
	 * Nombre de codes de récupération restants.
	 *
	 * @param int $user_id Identifiant.
	 * @return int
	 */
	public static function recovery_left( $user_id ) {
		$codes = get_user_meta( $user_id, self::META_RECOVERY, true );
		return is_array( $codes ) ? count( $codes ) : 0;
	}

	/**
	 * Vérifie un code TOTP pour un utilisateur et mémorise le pas accepté.
	 *
	 * @param int    $user_id Identifiant.
	 * @param string $code    Code saisi.
	 * @return bool
	 */
	public static function verify_totp( $user_id, $code ) {
		$secret = self::secret_of( $user_id );
		if ( false === $secret ) {
			return false;
		}
		$step = Totp::verify( $secret, $code, (int) get_user_meta( $user_id, self::META_STEP, true ) );
		if ( false === $step ) {
			return false;
		}
		update_user_meta( $user_id, self::META_STEP, $step );
		return true;
	}

	/**
	 * Vérifie un code de récupération et le consomme.
	 *
	 * @param int    $user_id Identifiant.
	 * @param string $input   Code saisi, avec ou sans tiret.
	 * @return bool
	 */
	public static function consume_recovery( $user_id, $input ) {
		$raw   = strtolower( preg_replace( '/[\s-]+/', '', (string) $input ) );
		$codes = get_user_meta( $user_id, self::META_RECOVERY, true );
		if ( ! is_array( $codes ) || 10 !== strlen( $raw ) ) {
			return false;
		}
		foreach ( $codes as $index => $hash ) {
			if ( wp_check_password( $raw, $hash ) ) {
				unset( $codes[ $index ] );
				update_user_meta( $user_id, self::META_RECOVERY, array_values( $codes ) );
				return true;
			}
		}
		return false;
	}

	/**
	 * TOTP ou récupération (pour désactiver ou régénérer depuis le profil).
	 *
	 * @param int    $user_id Identifiant.
	 * @param string $code    Code saisi.
	 * @return bool
	 */
	private static function verify_any( $user_id, $code ) {
		if ( self::verify_totp( $user_id, $code ) ) {
			return true;
		}
		if ( self::consume_recovery( $user_id, $code ) ) {
			Logger::log( '2fa_recovery_used', __( 'Code de récupération utilisé.', 'graphin-simple-security-ssl' ), array( 'user' => $user_id ), 'warning' );
			return true;
		}
		return false;
	}

	// Connexion.

	/**
	 * La requête est-elle la page de connexion WordPress ?
	 *
	 * @return bool
	 */
	private function is_login_page() {
		return isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] && ! defined( 'XMLRPC_REQUEST' ) && ! defined( 'REST_REQUEST' );
	}

	/**
	 * Interrompt la connexion d'un compte protégé après la vérification du mot de passe.
	 *
	 * @param \WP_User|\WP_Error|null $user     Résultat de l'authentification.
	 * @param string                  $username Identifiant.
	 * @param string                  $password Mot de passe.
	 * @return \WP_User|\WP_Error|null
	 */
	public function intercept( $user, $username, $password ) {
		unset( $username );
		if ( ! ( $user instanceof \WP_User ) || ! self::user_has_2fa( $user->ID ) ) {
			return $user;
		}
		// Session déjà valide (cookie) ou mot de passe d'application : pas de nouveau défi.
		if ( '' === (string) $password || did_action( 'application_password_did_authenticate' ) ) {
			return $user;
		}
		if ( ! $this->is_login_page() ) {
			return new \WP_Error( 'gsss_2fa_required', __( 'Ce compte utilise la double authentification : connectez-vous depuis la page de connexion WordPress.', 'graphin-simple-security-ssl' ) );
		}
		if ( $this->has_trusted_device( $user->ID ) ) {
			return $user;
		}

		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Connexion : pas de nonce WordPress.
		$token    = $this->create_pending( $user->ID, ! empty( $_POST['rememberme'] ), $redirect ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Idem.
		$this->render_challenge( $token );
		exit;
	}

	/**
	 * Clé de transient d'un jeton.
	 *
	 * @param string $token Jeton.
	 * @return string
	 */
	private function pending_key( $token ) {
		return 'gsss_2fa_' . substr( hash( 'sha256', $token ), 0, 40 );
	}

	/**
	 * Crée l'attente de second facteur.
	 *
	 * @param int    $user_id  Utilisateur.
	 * @param bool   $remember « Se souvenir de moi » de WordPress.
	 * @param string $redirect Adresse demandée après connexion.
	 * @return string Jeton.
	 */
	private function create_pending( $user_id, $remember, $redirect ) {
		$token = bin2hex( random_bytes( 16 ) );
		set_transient(
			$this->pending_key( $token ),
			array(
				'user_id'    => $user_id,
				'remember'   => (bool) $remember,
				'redirect'   => $redirect,
				'tries'      => 0,
				'email_hash' => '',
				'email_exp'  => 0,
				'email_sent' => 0,
			),
			self::TOKEN_TTL
		);
		return $token;
	}

	/**
	 * Attente enregistrée pour un jeton.
	 *
	 * @param string $token Jeton.
	 * @return array|false
	 */
	private function get_pending( $token ) {
		if ( ! preg_match( '/^[a-f0-9]{32}$/', $token ) ) {
			return false;
		}
		$pending = get_transient( $this->pending_key( $token ) );
		return is_array( $pending ) ? $pending : false;
	}

	/**
	 * Affiche l'écran du second facteur, dans le style de la page de connexion.
	 *
	 * @param string $token   Jeton d'attente.
	 * @param string $error   Message d'erreur.
	 * @param string $message Message d'information.
	 * @return void
	 */
	private function render_challenge( $token, $error = '', $message = '' ) {
		$errors = new \WP_Error();
		if ( '' !== $error ) {
			$errors->add( 'gsss_2fa_error', $error );
		}
		if ( '' !== $message ) {
			$errors->add( 'gsss_2fa_info', $message, 'message' );
		}
		login_header( __( 'Double authentification', 'graphin-simple-security-ssl' ), '', $errors );
		?>
		<form name="gsss2fa" id="gsss2fa" action="<?php echo esc_url( site_url( 'wp-login.php?action=gsss_2fa', 'login_post' ) ); ?>" method="post">
			<input type="hidden" name="gsss_token" value="<?php echo esc_attr( $token ); ?>">
			<p>
				<label for="gsss_code"><?php esc_html_e( 'Code de l\'application d\'authentification, ou code de récupération', 'graphin-simple-security-ssl' ); ?></label>
				<input type="text" name="gsss_code" id="gsss_code" class="input" value="" size="20" autocomplete="one-time-code" autocapitalize="off" autofocus>
			</p>
			<?php if ( Settings::get( 'login_2fa_remember' ) ) : ?>
				<p class="forgetmenot"><label><input type="checkbox" name="gsss_remember" value="1"> <?php esc_html_e( 'Se souvenir de cet appareil 30 jours', 'graphin-simple-security-ssl' ); ?></label></p>
			<?php endif; ?>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Valider', 'graphin-simple-security-ssl' ); ?>">
			</p>
			<p><button type="submit" name="gsss_send_email" value="1" class="button-link"><?php esc_html_e( 'Recevoir un code par email', 'graphin-simple-security-ssl' ); ?></button></p>
		</form>
		<p id="backtoblog"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( 'Retour à la connexion', 'graphin-simple-security-ssl' ); ?></a></p>
		<?php
		login_footer( 'gsss_code' );
	}

	/**
	 * Traite l'envoi du formulaire du second facteur.
	 *
	 * @return void
	 */
	public function handle_challenge() {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'POST' !== $method ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		$token   = isset( $_POST['gsss_token'] ) ? sanitize_text_field( wp_unslash( $_POST['gsss_token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Le jeton aléatoire fait office de preuve.
		$pending = $this->get_pending( $token );
		$user    = $pending ? get_userdata( $pending['user_id'] ) : false;
		if ( ! $pending || ! $user ) {
			login_header( __( 'Double authentification', 'graphin-simple-security-ssl' ), '', new \WP_Error( 'gsss_2fa_expired', __( 'La session a expiré. Reprenez la connexion depuis le début.', 'graphin-simple-security-ssl' ) ) );
			echo '<p id="nav"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Retour à la connexion', 'graphin-simple-security-ssl' ) . '</a></p>';
			login_footer();
			exit;
		}

		if ( ! empty( $_POST['gsss_send_email'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Idem.
			$this->send_email_code( $token, $pending, $user );
			exit;
		}

		$code = isset( $_POST['gsss_code'] ) ? sanitize_text_field( wp_unslash( $_POST['gsss_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Idem.
		if ( $pending['tries'] >= self::MAX_TRIES ) {
			delete_transient( $this->pending_key( $token ) );
			do_action(
				'wp_login_failed', // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Hook du cœur, déclenché pour les compteurs d'échecs.
				$user->user_login,
				new \WP_Error( 'gsss_2fa_locked', 'Trop d\'essais.' )
			);
			login_header( __( 'Double authentification', 'graphin-simple-security-ssl' ), '', new \WP_Error( 'gsss_2fa_locked', __( 'Trop d\'essais. Reprenez la connexion depuis le début.', 'graphin-simple-security-ssl' ) ) );
			echo '<p id="nav"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Retour à la connexion', 'graphin-simple-security-ssl' ) . '</a></p>';
			login_footer();
			exit;
		}

		if ( '' !== $code && $this->check_code( $user, $code, $pending ) ) {
			delete_transient( $this->pending_key( $token ) );
			if ( ! empty( $_POST['gsss_remember'] ) && Settings::get( 'login_2fa_remember' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Idem.
				$this->set_device_cookie( $user->ID );
			}
			$this->finish_login( $user, $pending );
		}

		++$pending['tries'];
		set_transient( $this->pending_key( $token ), $pending, self::TOKEN_TTL );
		Logger::log( '2fa_failed', __( 'Code de double authentification refusé.', 'graphin-simple-security-ssl' ), array( 'user' => $user->ID ), 'warning' );
		do_action(
			'wp_login_failed', // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Hook du cœur, déclenché pour les compteurs d'échecs.
			$user->user_login,
			new \WP_Error( 'gsss_2fa_invalid', 'Code incorrect.' )
		);
		$this->render_challenge( $token, __( '<strong>Erreur :</strong> code incorrect.', 'graphin-simple-security-ssl' ) );
		exit;
	}

	/**
	 * Teste le code saisi : email, TOTP, puis récupération.
	 *
	 * @param \WP_User $user    Utilisateur.
	 * @param string   $code    Code.
	 * @param array    $pending Attente (modifiée si le code email est consommé).
	 * @return bool
	 */
	private function check_code( $user, $code, &$pending ) {
		$digits = preg_replace( '/\s+/', '', $code );
		if ( '' !== $pending['email_hash'] && $pending['email_exp'] >= time() && hash_equals( $pending['email_hash'], hash_hmac( 'sha256', $digits, wp_salt( 'auth' ) ) ) ) {
			return true;
		}
		if ( self::verify_totp( $user->ID, $digits ) ) {
			return true;
		}
		if ( self::consume_recovery( $user->ID, $code ) ) {
			Logger::log( '2fa_recovery_used', __( 'Code de récupération utilisé à la connexion.', 'graphin-simple-security-ssl' ), array( 'user' => $user->ID ), 'warning' );
			wp_mail(
				$user->user_email,
				/* translators: %s: nom du site */
				sprintf( __( '[%s] Un code de récupération a été utilisé', 'graphin-simple-security-ssl' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
				/* translators: %d: nombre de codes restants */
				sprintf( __( "Un code de récupération vient de servir à ouvrir votre session. Il vous en reste %d.\n\nSi ce n'est pas vous, changez votre mot de passe et prévenez l'administrateur du site.", 'graphin-simple-security-ssl' ), self::recovery_left( $user->ID ) )
			);
			return true;
		}
		return false;
	}

	/**
	 * Envoie un code à six chiffres par email.
	 *
	 * @param string   $token   Jeton.
	 * @param array    $pending Attente.
	 * @param \WP_User $user    Utilisateur.
	 * @return void
	 */
	private function send_email_code( $token, $pending, $user ) {
		if ( time() - (int) $pending['email_sent'] < self::EMAIL_PAUSE ) {
			$this->render_challenge( $token, __( 'Un code vient d\'être envoyé. Patientez une minute avant d\'en demander un autre.', 'graphin-simple-security-ssl' ) );
			return;
		}
		$code                  = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
		$pending['email_hash'] = hash_hmac( 'sha256', $code, wp_salt( 'auth' ) );
		$pending['email_exp']  = time() + self::EMAIL_TTL;
		$pending['email_sent'] = time();
		set_transient( $this->pending_key( $token ), $pending, self::TOKEN_TTL );

		$sent = wp_mail(
			$user->user_email,
			/* translators: %s: nom du site */
			sprintf( __( '[%s] Votre code de connexion', 'graphin-simple-security-ssl' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			/* translators: %s: code à six chiffres */
			sprintf( __( "Votre code de connexion : %s\n\nIl est valable 10 minutes. Si vous n'avez pas demandé ce code, ignorez ce message et changez votre mot de passe.", 'graphin-simple-security-ssl' ), $code )
		);
		Logger::log( $sent ? '2fa_email_sent' : '2fa_email_failed', __( 'Code de connexion par email.', 'graphin-simple-security-ssl' ), array( 'user' => $user->ID ), $sent ? 'info' : 'error' );
		if ( $sent ) {
			$this->render_challenge( $token, '', __( 'Un code vient d\'être envoyé à l\'adresse email du compte.', 'graphin-simple-security-ssl' ) );
		} else {
			$this->render_challenge( $token, __( 'L\'email n\'a pas pu être envoyé.', 'graphin-simple-security-ssl' ) );
		}
	}

	/**
	 * Ouvre la session après un second facteur valide.
	 *
	 * @param \WP_User $user    Utilisateur.
	 * @param array    $pending Attente.
	 * @return void
	 */
	private function finish_login( $user, $pending ) {
		wp_set_auth_cookie( $user->ID, $pending['remember'] );
		wp_set_current_user( $user->ID );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Hook du cœur.
		Logger::log( '2fa_login', __( 'Connexion avec double authentification.', 'graphin-simple-security-ssl' ), array( 'user' => $user->ID ) );

		$requested = $pending['redirect'];
		$redirect  = '' !== $requested ? $requested : admin_url();
		$redirect  = apply_filters( 'login_redirect', $redirect, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Hook du cœur.
		wp_safe_redirect( $redirect );
		exit;
	}

	// Appareil de confiance.

	/**
	 * Signature d'un cookie d'appareil.
	 *
	 * @param string $payload Contenu à signer.
	 * @return string
	 */
	private function sign( $payload ) {
		return hash_hmac( 'sha256', $payload, wp_salt( 'auth' ) );
	}

	/**
	 * Pose le cookie « appareil de confiance » (30 jours).
	 *
	 * @param int $user_id Utilisateur.
	 * @return void
	 */
	private function set_device_cookie( $user_id ) {
		$token     = bin2hex( random_bytes( 16 ) );
		$expires   = time() + self::DEVICE_DAYS * DAY_IN_SECONDS;
		$devices   = get_user_meta( $user_id, self::META_DEVICES, true );
		$devices   = is_array( $devices ) ? $devices : array();
		$devices   = array_values(
			array_filter(
				$devices,
				function ( $device ) {
					return $device['expires'] > time();
				}
			)
		);
		$devices[] = array(
			'hash'    => hash( 'sha256', $token ),
			'expires' => $expires,
		);
		update_user_meta( $user_id, self::META_DEVICES, array_slice( $devices, -self::DEVICE_MAX ) );

		$payload = $user_id . '|' . $token . '|' . $expires;
		setcookie(
			self::DEVICE_COOKIE,
			$payload . '|' . $this->sign( $payload ),
			array(
				'expires'  => $expires,
				'path'     => COOKIEPATH,
				'domain'   => (string) COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	/**
	 * Cet appareil est-il de confiance pour cet utilisateur ?
	 *
	 * @param int $user_id Utilisateur.
	 * @return bool
	 */
	private function has_trusted_device( $user_id ) {
		if ( ! Settings::get( 'login_2fa_remember' ) || empty( $_COOKIE[ self::DEVICE_COOKIE ] ) ) {
			return false;
		}
		$parts = explode( '|', sanitize_text_field( wp_unslash( $_COOKIE[ self::DEVICE_COOKIE ] ) ) );
		if ( 4 !== count( $parts ) ) {
			return false;
		}
		list( $uid, $token, $expires, $signature ) = $parts;
		if ( (int) $uid !== (int) $user_id || (int) $expires < time() || ! hash_equals( $this->sign( $uid . '|' . $token . '|' . $expires ), $signature ) ) {
			return false;
		}
		$devices = get_user_meta( $user_id, self::META_DEVICES, true );
		if ( ! is_array( $devices ) ) {
			return false;
		}
		$hash = hash( 'sha256', $token );
		foreach ( $devices as $device ) {
			if ( hash_equals( $device['hash'], $hash ) && $device['expires'] > time() ) {
				return true;
			}
		}
		return false;
	}

	// Imposer la 2FA aux administrateurs.

	/**
	 * Situation d'un administrateur sans 2FA quand l'obligation est active.
	 *
	 * @param int $user_id Utilisateur.
	 * @return array|null end, expired, days_left, ou null si rien à signaler.
	 */
	public static function enforcement_for( $user_id ) {
		if ( ! Settings::get( 'login_2fa_enforce' ) || ! user_can( $user_id, 'manage_options' ) || self::user_has_2fa( $user_id ) ) {
			return null;
		}
		$since = (int) get_option( 'gsss_2fa_enforce_since', 0 );
		$since = $since ? $since : time();
		$end   = $since + (int) Settings::get( 'login_2fa_grace', 7 ) * DAY_IN_SECONDS;
		return array(
			'end'       => $end,
			'expired'   => time() >= $end,
			'days_left' => max( 0, (int) ceil( ( $end - time() ) / DAY_IN_SECONDS ) ),
		);
	}

	/**
	 * Délai de grâce passé : l'administrateur est renvoyé vers la configuration de sa 2FA.
	 *
	 * @return void
	 */
	public function enforce_redirect() {
		global $pagenow;
		if ( ! is_user_logged_in() || wp_doing_ajax() ) {
			return;
		}
		$status = self::enforcement_for( get_current_user_id() );
		if ( ! $status || ! $status['expired'] ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Lecture seule.
		if ( 'admin-post.php' === $pagenow || self::PAGE === $page ) {
			return;
		}
		wp_safe_redirect( $this->page_url() );
		exit;
	}

	/**
	 * Rappel sur toutes les pages d'administration tant que la 2FA n'est pas configurée.
	 *
	 * @return void
	 */
	public function reminder_notice() {
		$status = self::enforcement_for( get_current_user_id() );
		if ( ! $status ) {
			return;
		}
		$link = ' <a href="' . esc_url( $this->page_url() ) . '">' . esc_html__( 'Configurer la double authentification', 'graphin-simple-security-ssl' ) . '</a>';
		if ( $status['expired'] ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Graph\'in Security :', 'graphin-simple-security-ssl' ) . '</strong> ' . esc_html__( 'la double authentification est obligatoire pour les administrateurs. Configurez-la pour continuer.', 'graphin-simple-security-ssl' ) . wp_kses( $link, array( 'a' => array( 'href' => array() ) ) ) . '</p></div>';
			return;
		}
		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Graph\'in Security :', 'graphin-simple-security-ssl' ) . '</strong> ';
		/* translators: %d: nombre de jours */
		echo esc_html( sprintf( _n( 'la double authentification sera obligatoire pour les administrateurs dans %d jour.', 'la double authentification sera obligatoire pour les administrateurs dans %d jours.', $status['days_left'], 'graphin-simple-security-ssl' ), $status['days_left'] ) );
		echo wp_kses( $link, array( 'a' => array( 'href' => array() ) ) ) . '</p></div>';
	}

	// Pages et actions d'administration.

	/**
	 * Adresse de la page de configuration.
	 *
	 * @param array $args Paramètres supplémentaires.
	 * @return string
	 */
	public function page_url( $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::PAGE ), $args ), admin_url( 'admin.php' ) );
	}

	/**
	 * Page de configuration, accessible à tout utilisateur connecté, sans entrée de menu.
	 *
	 * @return void
	 */
	public function add_page() {
		$this->page_hook = (string) add_submenu_page( 'options.php', __( 'Double authentification', 'graphin-simple-security-ssl' ), __( 'Double authentification', 'graphin-simple-security-ssl' ), 'read', self::PAGE, array( $this, 'render_page' ) );
	}

	/**
	 * Assets : QR code seulement sur la page de configuration, confirmation sur les profils.
	 *
	 * @param string $hook_suffix Page admin.
	 * @return void
	 */
	public function enqueue( $hook_suffix ) {
		$on_page    = $hook_suffix === $this->page_hook;
		$on_profile = in_array( $hook_suffix, array( 'profile.php', 'user-edit.php' ), true );
		if ( ! $on_page && ! $on_profile ) {
			return;
		}
		$deps = array();
		if ( $on_page ) {
			wp_enqueue_script( 'gsss-qrcode', GSSS_URL . 'assets/qrcode.js', array(), '1.4.4', true );
			$deps[] = 'gsss-qrcode';
			wp_enqueue_style( 'gsss-admin', GSSS_URL . 'assets/admin.css', array(), GSSS_VERSION );
		}
		wp_enqueue_script( 'gsss-twofactor', GSSS_URL . 'assets/twofactor.js', $deps, GSSS_VERSION, true );
		wp_localize_script(
			'gsss-twofactor',
			'gsssTwofactor',
			array( 'confirm' => __( 'Réinitialiser la double authentification de cet utilisateur ?', 'graphin-simple-security-ssl' ) )
		);
	}

	/**
	 * Affiche la page de configuration de la 2FA de l'utilisateur courant.
	 *
	 * @return void
	 */
	public function render_page() {
		$gsss_user_id = get_current_user_id();
		$gsss_page    = $this;
		$gsss_notice  = isset( $_GET['gsss_notice'] ) ? sanitize_key( wp_unslash( $_GET['gsss_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Affichage d'un message.
		$gsss_codes   = get_transient( 'gsss_2fa_codes_' . $gsss_user_id );
		if ( false !== $gsss_codes ) {
			delete_transient( 'gsss_2fa_codes_' . $gsss_user_id ); // Affichés une seule fois.
		}
		$gsss_pending = Crypto::decrypt( (string) get_user_meta( $gsss_user_id, self::META_PENDING, true ) );
		$gsss_user    = wp_get_current_user();
		include GSSS_PATH . 'admin/views/twofactor.php';
	}

	/**
	 * Section affichée dans le profil : état, lien de configuration, réinitialisation par un administrateur.
	 *
	 * @param \WP_User $user Utilisateur affiché.
	 * @return void
	 */
	public function render_profile_section( $user ) {
		$own    = get_current_user_id() === $user->ID;
		$active = self::user_has_2fa( $user->ID );
		echo '<h2 id="gsss-2fa">' . esc_html__( 'Double authentification', 'graphin-simple-security-ssl' ) . '</h2><table class="form-table" role="presentation"><tr><th>' . esc_html__( 'État', 'graphin-simple-security-ssl' ) . '</th><td>';
		echo $active ? esc_html__( 'Activée', 'graphin-simple-security-ssl' ) : esc_html__( 'Non activée', 'graphin-simple-security-ssl' );
		if ( $own ) {
			echo ' <a class="button" href="' . esc_url( $this->page_url() ) . '">' . ( $active ? esc_html__( 'Gérer', 'graphin-simple-security-ssl' ) : esc_html__( 'Configurer', 'graphin-simple-security-ssl' ) ) . '</a>';
		}
		if ( $active && current_user_can( 'manage_options' ) && current_user_can( 'edit_user', $user->ID ) ) {
			echo ' <a class="button" data-gsss-confirm="1" href="' . esc_url( $this->reset_url( $user->ID ) ) . '">' . esc_html__( 'Réinitialiser', 'graphin-simple-security-ssl' ) . '</a>';
		}
		echo '</td></tr></table>';
	}

	/**
	 * Adresse de réinitialisation (nonce propre à l'utilisateur ciblé).
	 *
	 * @param int $user_id Utilisateur ciblé.
	 * @return string
	 */
	public function reset_url( $user_id ) {
		return wp_nonce_url( admin_url( 'admin-post.php?action=gsss_2fa_reset&user_id=' . (int) $user_id ), 'gsss_2fa_reset_' . (int) $user_id );
	}

	/**
	 * Retour vers la page de configuration avec un message.
	 *
	 * @param string $notice Code du message.
	 * @return void
	 */
	private function back( $notice ) {
		wp_safe_redirect( $this->page_url( array( 'gsss_notice' => $notice ) ) );
		exit;
	}

	/**
	 * Début de l'activation : secret généré, enregistré chiffré, en attente de confirmation.
	 *
	 * @return void
	 */
	public function action_begin() {
		check_admin_referer( 'gsss_2fa_begin' );
		if ( ! Crypto::available() ) {
			wp_die( esc_html__( 'Le chiffrement (openssl, AES-256-GCM) n\'est pas disponible sur ce serveur : la double authentification ne peut pas être activée.', 'graphin-simple-security-ssl' ) );
		}
		update_user_meta( get_current_user_id(), self::META_PENDING, Crypto::encrypt( Totp::generate_secret() ) );
		$this->back( 'begun' );
	}

	/**
	 * Abandon d'une activation en cours.
	 *
	 * @return void
	 */
	public function action_cancel() {
		check_admin_referer( 'gsss_2fa_cancel' );
		delete_user_meta( get_current_user_id(), self::META_PENDING );
		$this->back( 'cancelled' );
	}

	/**
	 * Confirmation par un premier code : la 2FA est activée et les codes de récupération affichés.
	 *
	 * @return void
	 */
	public function action_confirm() {
		check_admin_referer( 'gsss_2fa_confirm' );
		$user_id = get_current_user_id();
		$secret  = Crypto::decrypt( (string) get_user_meta( $user_id, self::META_PENDING, true ) );
		$code    = isset( $_POST['gsss_code'] ) ? sanitize_text_field( wp_unslash( $_POST['gsss_code'] ) ) : '';
		$step    = false === $secret ? false : Totp::verify( $secret, $code );
		if ( false === $step ) {
			$this->back( 'bad_code' );
		}
		$codes = self::enable_for_user( $user_id, $secret );
		if ( false === $codes ) {
			$this->back( 'crypto_error' );
		}
		update_user_meta( $user_id, self::META_STEP, $step );
		set_transient( 'gsss_2fa_codes_' . $user_id, $codes, 300 );
		Logger::log( '2fa_enabled', __( 'Double authentification activée.', 'graphin-simple-security-ssl' ), array( 'user' => $user_id ) );
		$this->back( 'enabled' );
	}

	/**
	 * Désactivation, après un code valide.
	 *
	 * @return void
	 */
	public function action_disable() {
		check_admin_referer( 'gsss_2fa_disable' );
		$user_id = get_current_user_id();
		$code    = isset( $_POST['gsss_code'] ) ? sanitize_text_field( wp_unslash( $_POST['gsss_code'] ) ) : '';
		if ( ! self::user_has_2fa( $user_id ) || ! self::verify_any( $user_id, $code ) ) {
			$this->back( 'bad_code' );
		}
		self::disable_for_user( $user_id );
		$this->notify_user( $user_id, __( 'La double authentification a été désactivée sur votre compte.', 'graphin-simple-security-ssl' ) );
		Logger::log( '2fa_disabled', __( 'Double authentification désactivée.', 'graphin-simple-security-ssl' ), array( 'user' => $user_id ), 'warning' );
		$this->back( 'disabled' );
	}

	/**
	 * Nouveaux codes de récupération, après un code valide.
	 *
	 * @return void
	 */
	public function action_regen() {
		check_admin_referer( 'gsss_2fa_regen' );
		$user_id = get_current_user_id();
		$code    = isset( $_POST['gsss_code'] ) ? sanitize_text_field( wp_unslash( $_POST['gsss_code'] ) ) : '';
		if ( ! self::user_has_2fa( $user_id ) || ! self::verify_any( $user_id, $code ) ) {
			$this->back( 'bad_code' );
		}
		set_transient( 'gsss_2fa_codes_' . $user_id, self::new_recovery_codes( $user_id ), 300 );
		Logger::log( '2fa_codes_regenerated', __( 'Codes de récupération régénérés.', 'graphin-simple-security-ssl' ), array( 'user' => $user_id ) );
		$this->back( 'regenerated' );
	}

	/**
	 * Réinitialisation de la 2FA d'un autre utilisateur par un administrateur.
	 *
	 * @return void
	 */
	public function action_reset() {
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		check_admin_referer( 'gsss_2fa_reset_' . $user_id );
		if ( ! $user_id || ! current_user_can( 'manage_options' ) || ! current_user_can( 'edit_user', $user_id ) ) {
			wp_die( esc_html__( 'Accès refusé.', 'graphin-simple-security-ssl' ), '', array( 'response' => 403 ) );
		}
		self::disable_for_user( $user_id );
		$this->notify_user( $user_id, __( 'La double authentification de votre compte a été réinitialisée par un administrateur. Vous pouvez la reconfigurer depuis votre profil.', 'graphin-simple-security-ssl' ) );
		Logger::log( '2fa_reset', __( 'Double authentification réinitialisée par un administrateur.', 'graphin-simple-security-ssl' ), array( 'user' => $user_id ), 'warning' );
		wp_safe_redirect( add_query_arg( 'gsss_notice', 'reset', admin_url( 'admin.php?page=gsss-login' ) ) );
		exit;
	}

	/**
	 * Prévient l'utilisateur par email.
	 *
	 * @param int    $user_id Utilisateur.
	 * @param string $message Texte.
	 * @return void
	 */
	private function notify_user( $user_id, $message ) {
		$user = get_userdata( $user_id );
		if ( $user ) {
			/* translators: %s: nom du site */
			wp_mail( $user->user_email, sprintf( __( '[%s] Double authentification', 'graphin-simple-security-ssl' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ), $message );
		}
	}
}
