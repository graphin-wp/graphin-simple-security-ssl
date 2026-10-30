/* Graph'in Simple Security SSL : double authentification (QR code, confirmations, copie). */
( function () {
	'use strict';

	var cfg = window.gsssTwofactor || {};

	var qr = document.getElementById( 'gsss-qr' );
	if ( qr && window.qrcode ) {
		var code = window.qrcode( 0, 'M' );
		code.addData( qr.getAttribute( 'data-uri' ) );
		code.make();
		qr.innerHTML = code.createSvgTag( 5, 4, 'QR code', 'QR code de configuration' );
	}

	Array.prototype.forEach.call( document.querySelectorAll( '[data-gsss-confirm]' ), function ( link ) {
		link.addEventListener( 'click', function ( event ) {
			if ( ! window.confirm( cfg.confirm || '' ) ) {
				event.preventDefault();
			}
		} );
	} );

	Array.prototype.forEach.call( document.querySelectorAll( '[data-gsss-copy]' ), function ( button ) {
		button.addEventListener( 'click', function () {
			var source = document.getElementById( button.getAttribute( 'data-gsss-copy' ) );
			if ( source ) {
				source.select();
				if ( navigator.clipboard && navigator.clipboard.writeText ) {
					navigator.clipboard.writeText( source.value );
				} else {
					document.execCommand( 'copy' );
				}
			}
		} );
	} );
}() );
