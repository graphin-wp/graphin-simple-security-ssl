/* Graph'in Simple Security SSL : JS admin (vanilla). */
( function () {
	'use strict';

	if ( ! window.gsssAdmin ) {
		return;
	}
	var cfg = window.gsssAdmin;

	/**
	 * Appel AJAX admin avec nonce.
	 *
	 * @param {string} action Action AJAX.
	 * @param {Object} extra  Champs supplémentaires.
	 * @return {Promise<Object>} Réponse JSON.
	 */
	function post( action, extra ) {
		var data = new FormData();
		data.append( 'action', action );
		data.append( 'nonce', cfg.nonce );
		Object.keys( extra || {} ).forEach( function ( key ) {
			data.append( key, extra[ key ] );
		} );
		return fetch( cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: data } ).then( function ( response ) {
			return response.json();
		} );
	}

	var mailButton = document.getElementById( 'gsss-test-mail' );
	var mailOutput = document.getElementById( 'gsss-test-mail-result' );
	if ( mailButton && mailOutput ) {
		mailButton.addEventListener( 'click', function () {
			mailButton.disabled = true;
			mailOutput.textContent = cfg.i18n.sending;
			post( 'gsss_send_test_mail' )
				.then( function ( json ) {
					mailOutput.textContent = json && json.data && json.data.message ? json.data.message : cfg.i18n.error;
				} )
				.catch( function () {
					mailOutput.textContent = cfg.i18n.error;
				} )
				.then( function () {
					mailButton.disabled = false;
				} );
		} );
	}

	var scanButton = document.getElementById( 'gsss-vuln-scan' );
	var scanOutput = document.getElementById( 'gsss-vuln-scan-result' );
	if ( scanButton && scanOutput ) {
		var fail = function ( message ) {
			scanOutput.textContent = message || cfg.i18n.error;
			scanButton.disabled = false;
		};
		var step = function ( start ) {
			post( 'gsss_vuln_scan_step', start ? { start: 1 } : {} )
				.then( function ( json ) {
					if ( ! json || ! json.success ) {
						fail( json && json.data && json.data.message );
						return;
					}
					var state = json.data;
					if ( state.done ) {
						scanOutput.textContent = cfg.i18n.scanDone;
						window.location.reload();
						return;
					}
					scanOutput.textContent = cfg.i18n.scanning.replace( '%1$s', state.processed ).replace( '%2$s', state.total );
					step( false );
				} )
				.catch( function () {
					fail();
				} );
		};
		scanButton.addEventListener( 'click', function () {
			scanButton.disabled = true;
			scanOutput.textContent = cfg.i18n.sending;
			step( true );
		} );
	}
}() );
