<?php
/**
 * Test en ligne de commande de VulnScanner::is_affected(), sans WordPress.
 * Usage : php bin/test-vuln-scanner.php
 * Hors du zip (bin/ est dans .distignore).
 *
 * @package Graphin\SimpleSecurity
 */

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.Security.EscapeOutput.OutputNotEscaped

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

define( 'ABSPATH', __DIR__ . '/' );
require dirname( __DIR__ ) . '/includes/class-vuln-scanner.php';

use Graphin\SimpleSecurity\VulnScanner;

/**
 * Faille normalisée minimale.
 *
 * @param string|null $min    Borne basse.
 * @param string      $min_op Opérateur bas.
 * @param string|null $max    Borne haute.
 * @param string      $max_op Opérateur haut.
 * @return array
 */
function gsss_test_vuln( $min, $min_op, $max, $max_op ) {
	return array(
		'min'    => $min,
		'min_op' => $min_op,
		'max'    => $max,
		'max_op' => $max_op,
	);
}

$gsss_cases = array(
	// CVE-2022-50972 (WooCommerce) : seule la 7.1.0 est touchée.
	array( '11.3.0', gsss_test_vuln( null, '', '7.1.0', 'eq' ), false, 'eq : version récente non concernée' ),
	array( '7.1.0', gsss_test_vuln( null, '', '7.1.0', 'eq' ), true, 'eq : version exacte concernée' ),
	array( '7.0.9', gsss_test_vuln( null, '', '7.1.0', 'eq' ), false, 'eq : version antérieure non concernée' ),
	array( '7.1.0', gsss_test_vuln( '7.1.0', 'eq', null, '' ), true, 'eq en borne basse' ),
	array( '2.0', gsss_test_vuln( null, '', '1.0', 'ne' ), true, 'ne : autre version concernée' ),
	array( '1.0', gsss_test_vuln( null, '', '1.0', 'ne' ), false, 'ne : même version non concernée' ),
	array( '6.0', gsss_test_vuln( '5.0', 'ge', '6.2', 'lt' ), true, 'plage ge/lt : dedans' ),
	array( '6.2', gsss_test_vuln( '5.0', 'ge', '6.2', 'lt' ), false, 'plage ge/lt : borne haute exclue' ),
	array( '4.9', gsss_test_vuln( '5.0', 'ge', '6.2', 'lt' ), false, 'plage ge/lt : sous la borne basse' ),
	array( '5.0', gsss_test_vuln( '5.0', 'gt', '6.2', 'le' ), false, 'plage gt/le : borne basse exclue' ),
	array( '6.2', gsss_test_vuln( '5.0', 'gt', '6.2', 'le' ), true, 'plage gt/le : borne haute incluse' ),
	array( '3.0', gsss_test_vuln( null, '', null, '' ), true, 'sans borne : concernée' ),
	array( '3.0', gsss_test_vuln( null, '', '1.0', 'zz' ), true, 'opérateur inconnu : reste concernée' ),
	array( '3.0', gsss_test_vuln( '9.0', 'zz', null, '' ), true, 'opérateur inconnu en borne basse : reste concernée' ),
);

$gsss_failed = 0;
foreach ( $gsss_cases as $gsss_case ) {
	list( $gsss_version, $gsss_vuln, $gsss_expected, $gsss_label ) = $gsss_case;
	$gsss_ok = VulnScanner::is_affected( $gsss_version, $gsss_vuln ) === $gsss_expected;
	if ( ! $gsss_ok ) {
		++$gsss_failed;
	}
	echo ( $gsss_ok ? 'OK    ' : 'ÉCHEC ' ) . $gsss_label . PHP_EOL;
}
echo count( $gsss_cases ) - $gsss_failed . '/' . count( $gsss_cases ) . ' tests réussis' . PHP_EOL;
exit( $gsss_failed > 0 ? 1 : 0 );
