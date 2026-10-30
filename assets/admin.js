/* Graph'in Simple Security SSL : JS admin (vanilla). */
( function () {
	'use strict';

	var button = document.getElementById( 'gsss-test-mail' );
	var output = document.getElementById( 'gsss-test-mail-result' );
	if ( ! button || ! output || ! window.gsssAdmin ) {
		return;
	}

	button.addEventListener( 'click', function () {
		var data = new FormData();
		data.append( 'action', 'gsss_send_test_mail' );
		data.append( 'nonce', window.gsssAdmin.nonce );

		button.disabled = true;
		output.textContent = window.gsssAdmin.i18n.sending;

		fetch( window.gsssAdmin.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: data } )
			.then( function ( response ) {
				return response.json();
			} )
			.then( function ( json ) {
				output.textContent = json && json.data && json.data.message ? json.data.message : window.gsssAdmin.i18n.error;
			} )
			.catch( function () {
				output.textContent = window.gsssAdmin.i18n.error;
			} )
			.then( function () {
				button.disabled = false;
			} );
	} );
}() );
