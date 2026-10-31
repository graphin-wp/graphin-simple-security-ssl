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

	var testButton = document.getElementById( 'gsss-test-headers' );
	var testStatus = document.getElementById( 'gsss-test-headers-status' );
	var testTable = document.getElementById( 'gsss-test-headers-table' );
	if ( testButton && testStatus && testTable ) {
		testButton.addEventListener( 'click', function () {
			testButton.disabled = true;
			testStatus.textContent = cfg.i18n.sending;
			post( 'gsss_test_headers' )
				.then( function ( json ) {
					if ( ! json || ! json.success ) {
						testStatus.textContent = json && json.data && json.data.message ? json.data.message : cfg.i18n.error;
						return;
					}
					var body = testTable.querySelector( 'tbody' );
					while ( body.firstChild ) {
						body.removeChild( body.firstChild );
					}
					json.data.rows.forEach( function ( row ) {
						var tr = document.createElement( 'tr' );
						var present = null !== row.value;
						[ row.name, present ? cfg.i18n.present : cfg.i18n.absent, present ? row.value : '' ].forEach( function ( text, index ) {
							var td = document.createElement( 'td' );
							td.textContent = text;
							if ( 1 === index ) {
								td.className = present ? 'gsss-ok' : 'gsss-ko';
							}
							tr.appendChild( td );
						} );
						body.appendChild( tr );
					} );
					testTable.classList.remove( 'gsss-hidden' );
					testStatus.textContent = '';
				} )
				.catch( function () {
					testStatus.textContent = cfg.i18n.error;
				} )
				.then( function () {
					testButton.disabled = false;
				} );
		} );
	}

	var detectButton = document.getElementById( 'gsss-ssl-detect' );
	var detectStatus = document.getElementById( 'gsss-ssl-detect-status' );
	if ( detectButton && detectStatus ) {
		detectButton.addEventListener( 'click', function () {
			detectButton.disabled = true;
			detectStatus.textContent = cfg.i18n.sending;
			post( 'gsss_ssl_detect' )
				.then( function ( json ) {
					if ( json && json.success ) {
						window.location.reload();
						return;
					}
					detectStatus.textContent = json && json.data && json.data.message ? json.data.message : cfg.i18n.error;
					detectButton.disabled = false;
				} )
				.catch( function () {
					detectStatus.textContent = cfg.i18n.error;
					detectButton.disabled = false;
				} );
		} );
	}

	Array.prototype.forEach.call( document.querySelectorAll( '[data-gsss-confirm-msg]' ), function ( form ) {
		form.addEventListener( 'submit', function ( event ) {
			if ( ! window.confirm( form.getAttribute( 'data-gsss-confirm-msg' ) ) ) {
				event.preventDefault();
			}
		} );
	} );

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

	Array.prototype.forEach.call( document.querySelectorAll( '[data-gsss-copy]' ), function ( button ) {
		button.addEventListener( 'click', function () {
			var source = document.getElementById( button.getAttribute( 'data-gsss-copy' ) );
			var result = button.parentNode.querySelector( '.gsss-copy-result' );
			if ( ! source ) {
				return;
			}
			var done = function ( ok ) {
				if ( result ) {
					result.textContent = ok ? cfg.i18n.copied : cfg.i18n.copyFailed;
				}
			};
			source.select();
			if ( navigator.clipboard && navigator.clipboard.writeText ) {
				navigator.clipboard.writeText( source.value ).then( function () {
					done( true );
				}, function () {
					done( false );
				} );
			} else {
				done( document.execCommand( 'copy' ) );
			}
		} );
	} );
}() );
