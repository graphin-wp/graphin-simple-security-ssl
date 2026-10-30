<?php
/**
 * Gabarit commun : navigation à gauche, carte à droite.
 *
 * @package Graphin\SimpleSecurity
 *
 * @var string $slug  Page courante.
 * @var string $title Titre de la page.
 * @var string $view  Chemin de la vue.
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap gsss-wrap">
	<h1 class="gsss-title"><?php echo esc_html( $title ); ?></h1>
	<div class="gsss-layout">
		<nav class="gsss-nav" aria-label="<?php esc_attr_e( 'Navigation Graph\'in Security', 'graphin-simple-security-ssl' ); ?>">
			<?php foreach ( \Graphin\SimpleSecurity\Admin\Admin::pages() as $gsss_nav_slug => $gsss_nav_label ) : ?>
				<a class="gsss-nav__item<?php echo $gsss_nav_slug === $slug ? ' is-active' : ''; ?>" href="<?php echo esc_url( admin_url( 'admin.php?page=' . $gsss_nav_slug ) ); ?>"><?php echo esc_html( $gsss_nav_label ); ?></a>
			<?php endforeach; ?>
		</nav>
		<main class="gsss-main">
			<?php require $view; ?>
		</main>
	</div>
</div>
