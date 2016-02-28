/*
 * CACKey ChromeOS chrome.certificateProvider Implementation
 */

function onCertificatesRejected(rejectedCerts) {
	// If certificates were rejected by the API, log an error, for example.
	console.error(rejectedCerts.length + ' certificates were rejected.');
	return;
}

/*
 * Handle for the CACKey NaCl Target
 */
var cackeyHandle = null;
var cackeyPCSCHandle = null;
var cackeyPCSCHandleUsable = false;

/*
 * Handle and ID for outstanding callbacks
 */
var cackeyOutstandingCallbacks = {}
var cackeyOutstandingCallbackCounter = -1;

/*
 * Communication with the PIN entry window
 */
var pinWindowPINValue = "";
var pinWindowPreviousHandle = null;

/*
 * Messages that may need to be retried after getting a PIN
 */
var cackeyMessagesToRetry = [];

/*
 * Stored PIN for a given certificate
 */
var cackeyCertificateToPINMap = {};

/*
 * Callbacks to perform after PCSC comes online
 */
cackeyCallbackAfterInit = [];

/*
 * Compute a text-based handle for a certificate to be hashed by
 */
function cackeyCertificateToPINID(certificate) {
	var id;
	var certificateArray;

	id = "";

	certificateArray = new Uint8Array(certificate);

	certificateArray.map(
		function(byte) {
			id += ("0" + byte.toString(16)).slice(-2);
		}
	);

	delete certificateArray;

	return(id);
}

/*
 * Handle a response from the NaCl side regarding certificates available
 */
function cackeyMessageIncomingListCertificates(message, chromeCallback) {
	var idx;
	var certificates = [];

	for (idx = 0; idx < message.certificates.length; idx++) {
		certificates.push(
			{
				certificate: message.certificates[idx],
				supportedHashes: ['SHA1', 'SHA256', 'MD5_SHA1']
			}
		);
	}

	chromeCallback(certificates,
		function(rejectedCerts) {
			if (chrome.runtime.lastError) {
				return;
			}

			if (rejectedCerts.length !== 0) {
				onCertificatesRejected(rejectedCerts);
			}

			return;
		}
	);

	return;
}

/*
 * Handle a response from the NaCl side regarding signing a message
 */
function cackeyMessageIncomingSignMessage(message, chromeCallback) {
	var payload;

	payload = message.signedData;

	chromeCallback(payload);

	return;
}

/*
 * Handle an incoming message from the NaCl side and pass it off to
 * one of the handlers above for actual formatting and passing to
 * the callback
 *
 * If an error occured, invoke the callback with no arguments.
 */
function cackeyMessageIncoming(messageEvent) {
	var nextFunction = null;
	var chromeCallback = null;

	if (messageEvent.data.target != "cackey") {
		return;
	}

	if (GoogleSmartCard.IS_DEBUG_BUILD) {
		console.log("START MESSAGE");
		console.log(messageEvent.data);
		console.log("END MESSAGE");
	}

	/*
	 * If we failed for some reason and we have a certificate in the original
	 * request then forget any PIN associated with that certificate
	 */
	if (messageEvent.data.status != "success") {
		if (messageEvent.data.originalrequest) {
			if (messageEvent.data.originalrequest.certificate) {
				delete cackeyCertificateToPINMap[cackeyCertificateToPINID(messageEvent.data.originalrequest.certificate)];
			}
		}
	}

	if (messageEvent.data.command == "init" && messageEvent.data.status == "success") {
		if (GoogleSmartCard.IS_DEBUG_BUILD) {
			console.log("[cackey] Initialization completed, resending any queued messages");
		}

		cackeyInitPCSCCompleted();
	}

	if (messageEvent.data.id == null) {
		return;
	}

	chromeCallback = cackeyOutstandingCallbacks[messageEvent.data.id];

	if (chromeCallback == null) {
		console.error("[cackey] Discarding outdated message");

		return;
	}

	switch (messageEvent.data.status) {
		case "error":
			console.error("[cackey] Failed to execute command '" + messageEvent.data.command + "': " + messageEvent.data.error);

			chromeCallback();

			break;
		case "retry":
			/*
			 * Add the new request to the queue of events to process when the PIN
			 * prompt is terminated.
			 */
			cackeyMessagesToRetry.push(messageEvent);

			if (pinWindowPreviousHandle) {
				/*
				 * An existing PIN entry is in progress
				 * Just add the request to the queue (above) and wait
				 */

				return;
			}

			/*
			 * Set the handle to an invalid (but non-null) value until the window
			 * is created in case we are invoked again soon.
			 */
			pinWindowPreviousHandle = "invalid";

			chrome.app.window.create("pin.html", {
				"id": "cackeyPINEntry",
				"resizable": false,
				"alwaysOnTop": true,
				"focused": true,
				"visibleOnAllWorkspaces": true,
				"innerBounds": {
					"width": 350,
					"minWidth": 350,
					"height": 135,
					"minHeight": 135
				}
			}, function(pinWindow) {
				/*
				 * Set the PIN value to blank
				 */
				pinWindowPINValue = "";

				if (!pinWindow) {
					console.error("[cackey] No window was provided for PIN entry, this will not go well.");

					return;
				}

				pinWindowPreviousHandle = pinWindow;

				pinWindow.drawAttention();
				pinWindow.focus();

				/*
				 * Register a handler to handle the window being closed without
				 * having sent anything
				 */
				pinWindow.onClosed.addListener(function() {
					var messageIdx;

					pinWindowPreviousHandle = null;

					for (messageIdx = 0; messageIdx < cackeyMessagesToRetry.length; messageIdx++) {
						var tmpMessageEvent;

						tmpMessageEvent = cackeyMessagesToRetry[messageIdx];

						if (pinWindowPINValue == "") {
							if (GoogleSmartCard.IS_DEBUG_BUILD) {
								console.log("[cackey] The PIN dialog was closed without gathering a PIN, treating it as a failure.");
							}

							tmpMessageEvent.data.status = "error";
							tmpMessageEvent.data.error = "PIN window closed without a PIN being provided";

							cackeyMessageIncoming(tmpMessageEvent);
						} else {
							tmpMessageEvent.data.originalrequest.pin = pinWindowPINValue;

							cackeyCertificateToPINMap[cackeyCertificateToPINID(tmpMessageEvent.data.originalrequest.certificate)] = pinWindowPINValue;

							cackeyInitPCSC(function() {
								cackeyHandle.postMessage(tmpMessageEvent.data.originalrequest);
							});
						}
					}


					/*
					 * Delete the existing handle and create a new one
					 */
					delete cackeyMessagesToRetry;

					cackeyMessagesToRetry = [];

					/*
					 * We are done fetching the user PIN, clear the value
					 */
					pinWindowPINValue = "";

					return;
				})

				/*
				 * Pass this message off to the other window so that it may resubmit the request.
				 */
				pinWindow.contentWindow.parentWindow = window;
				pinWindow.contentWindow.messageEvent = messageEvent;

				return;
			});

			/*
			 * We return here instead of break to avoid deleting the callback
			 * entry.
			 */
			return;
		case "success":
			switch (messageEvent.data.command) {
				case "listcertificates":
					nextFunction = cackeyMessageIncomingListCertificates;

					break;
				case "sign":
					nextFunction = cackeyMessageIncomingSignMessage;

					break;
			}

			break;
	}

	if (nextFunction != null) {
		nextFunction(messageEvent.data, chromeCallback);
	}

	delete cackeyOutstandingCallbacks[messageEvent.data.id];

	return;
}

/*
 * Handler for messages from Chrome related to listing certificates
 */
function cackeyListCertificates(chromeCallback) {
	var callbackId;

	if (GoogleSmartCard.IS_DEBUG_BUILD) {
		console.log("[cackey] Asked to provide a list of certificates -- throwing that request over to the NaCl side... ");
	}

	callbackId = cackeyOutstandingCallbackCounter + 1;

	cackeyInitPCSC(function() {
		cackeyHandle.postMessage(
			{
				'target': "cackey",
				'command': "listcertificates",
				'id': callbackId
			}
		);

		cackeyOutstandingCallbackCounter = callbackId;
		cackeyOutstandingCallbacks[callbackId] = chromeCallback;

		if (GoogleSmartCard.IS_DEBUG_BUILD) {
			console.log("[cackey] Thrown.");
		}
	});

	return;
}

/*
 * Handler for messages from Chrome related to signing a hash of some sort
 */
function cackeySignMessage(signRequest, chromeCallback) {
	var callbackId;
	var command;
	var certificateId;
	var digest, digestHeader;

	/*
	 * Prefix the digest with the ASN.1 header required of it
	 */
	switch (signRequest.hash) {
		case "SHA1":
			digestHeader = new Uint8Array([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]);
			break;
		case "SHA256":
			digestHeader = new Uint8Array([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]);
			break;
		case "MD5_SHA1":
			digestHeader = new Uint8Array();
			break;
		default:
			console.error("[cackey] Asked to sign a message with a hash we do not support: " + signRequest.hash);

			chromeCallback();

			return;
	}

	digest = new Uint8Array(digestHeader.length + signRequest.digest.byteLength);
	digest.set(digestHeader, 0);
	digest.set(new Uint8Array(signRequest.digest), digestHeader.length);

	delete digestHeader;

	if (GoogleSmartCard.IS_DEBUG_BUILD) {
		console.log("[cackey] Asked to sign a message -- throwing that request over to the NaCl side... ");
	}

	callbackId = cackeyOutstandingCallbackCounter + 1;

	command = {
		'target': "cackey",
		'command': "sign",
		'id': callbackId,
		'certificate': signRequest.certificate,
		'data': digest.buffer
	};

	certificateId = cackeyCertificateToPINID(command.certificate);

	if (cackeyCertificateToPINMap[certificateId]) {
		command.pin = cackeyCertificateToPINMap[certificateId];
	}

	cackeyInitPCSC(function() {
		cackeyHandle.postMessage(command);

		cackeyOutstandingCallbackCounter = callbackId;
		cackeyOutstandingCallbacks[callbackId] = chromeCallback;

		if (GoogleSmartCard.IS_DEBUG_BUILD) {
			console.log("[cackey] Thrown.");
		}
	});

	return;
}

/*
 * Unititalizes the CACKey PCSC connection
 */
function cackeyUninitPCSC() {
	console.log("[cackey] cackeyUninitPCSC() called");

	if (cackeyPCSCHandle != null) {
		console.log("[cackey] Deleting PCSC handle");

		delete cackeyPCSCHandle;

		cackeyPCSCHandle = null;
	}

	cackeyPCSCHandleUsable = false;

	console.log("[cackey] cackeyUninitPCSC() returning");

	return;
}

/*
 * Uninitializes CACKey (probably due to a crash)
 */
function cackeyUninit() {
	console.log("[cackey] cackeyUninit() called");

	if (chrome.certificateProvider) {
		console.log("[cackey] Unregistered Chrome certificate handlers");

		chrome.certificateProvider.onCertificatesRequested.removeListener(cackeyListCertificates);
		chrome.certificateProvider.onSignDigestRequested.removeListener(cackeySignMessage);
	}

	cackeyUninitPCSC();

	if (cackeyHandle != null) {
		console.log("[cackey] Deleting PNaCl module");

		try {
			document.body.removeChild(cackeyHandle);
		} catch (e) { }

		delete cackeyHandle;

		cackeyHandle = null;
	}

	console.log("[cackey] cackeyUninit() complete");

	return;
}

/*
 * Restarts CACKey
 */
function cackeyRestart() {
	cackeyUninit();
	cackeyInit();

	return;
}

function cackeyInitGlobalState() {
	cackeyOutstandingCallbacks = {};
};

/*
 * Handle a CACKey crash (probably due to loss of connectivity to the PCSC daemon)
 */
function cackeyCrash() {
	/*
	 * De-initialize CACKey
	 */
	cackeyUninit();

	/*
	 * Reinitialize global state
	 */
	cackeyInitGlobalState();

	/*
	 * Schedule the restart to occur in 30 seconds in case we really are
	 * not working.
	 */
	setTimeout(cackeyInit, 30000);

	return;
}

function cackeyInitPCSCCompleted() {
	var idx;

	cackeyPCSCHandleUsable = true;

	for (idx = 0; idx < cackeyCallbackAfterInit.length; idx++) {
		if (!cackeyCallbackAfterInit[idx]) {
			continue;
		}

		cackeyCallbackAfterInit[idx]();
	}

	delete cackeyCallbackAfterInit;

	cackeyCallbackAfterInit = [];

	return;
}

/*
 * Initialize the PCSC connection
 */
function cackeyInitPCSC(callbackAfterInit) {
	/*
	 * Start the Google PCSC Interface
	 */

	console.log("[cackey] cackeyInitPCSC() called");

	/*
	 * Queue this callback to be completed when initialization is complete
	 */
	if (callbackAfterInit) {
		cackeyCallbackAfterInit.push(callbackAfterInit);
	}

	/*
	 * No additional work is required
	 */

	if (cackeyPCSCHandle) {
		console.log("[cackey] PCSC handle is already valid, nothing to do.");

		if (cackeyPCSCHandleUsable) {
			cackeyInitPCSCCompleted();
		}

		return;
	}

	/*
	 * Sanely initialize this
	 */
	cackeyPCSCHandleUsable = false;

	/*
	 * Initialize the CACKey PNaCl module if needed
	 */
	if (cackeyHandle == null) {
		cackeyInit();
	}

	/*
	 * Initialize CACKey with the correct handle to talk to the Google Smartcard Manager App
	 */
	cackeyHandle.postMessage(
		{
			"target": "cackey",
			"command": "init",
			"smartcardManagerAppId": "khpfeaanjngmcnplbdlpegiifgpfgdco"
		}
	);

	/*
	 * Initialize the PCSC NaCl interface
	 */
	cackeyPCSCHandle = new GoogleSmartCard.PcscNacl(cackeyHandle);

	console.log("[cackey] cackeyInitPCSC() complete");

	return;
}

/*
 * Finish performing initialization that must wait until we have loaded the CACKey module
 */
function cackeyInitLoaded(messageEvent) {
	console.log("[cackey] Loaded CACKey PNaCl Module");

	/* Register listeners with Chrome */
	if (chrome.certificateProvider) {
		console.log("[cackey] Registered Certificate handlers with Chrome");

		chrome.certificateProvider.onCertificatesRequested.addListener(cackeyListCertificates);
		chrome.certificateProvider.onSignDigestRequested.addListener(cackeySignMessage);
	}

	return;
}

/*
 * Initialize CACKey and the PCSC library from Google
 */
function cackeyInit() {
	var elementEmbed;
	var forceLoadElement;

	/* Log that we are operational */
	console.log("[cackey] cackeyInit(): Called.");

	/*
	 * Do not initialize multiple times
	 */
	if (cackeyHandle != null) {
		console.log("[cackey] cackeyInit(): Already initialized.  Returning.");

		return;
	}

	/* Verify that we can register callbacks */
	if (!chrome.certificateProvider) {
		if (!GoogleSmartCard.IS_DEBUG_BUILD) {
			console.error("[cackey] This extension only works on ChromeOS!");

			return;
		} else {
			console.log("[cackey] This extension only works on ChromeOS, but you appear to be debugging it -- trying anyway.");
		}
	}

	elementEmbed = document.createElement('embed');
	elementEmbed.type = "application/x-pnacl";
	elementEmbed.width = 0;
	elementEmbed.height = 0;
	elementEmbed.src = "cackey.nmf";
	elementEmbed.id = "cackeyModule";
	elementEmbed.addEventListener('error', function(messageEvent) { console.error("Error loading CACKey PNaCl Module: " + messageEvent.data); }, true);
	elementEmbed.addEventListener('load', cackeyInitLoaded, true);
	elementEmbed.addEventListener('crash', cackeyCrash, true);
	elementEmbed.addEventListener('message', cackeyMessageIncoming, true);

	cackeyHandle = elementEmbed;

	document.body.appendChild(cackeyHandle)

	/*
	 * Force the browser to load the element
	 * by requesting its position
	 */
	forceLoadElement = cackeyHandle.offsetTop;

	console.log("[cackey] cackeyInit(): Completed.  Returning.");

	return;
}

/*
 * Initialize the CACKey Chrome Application
 */
function cackeyAppInit() {
	var oldOnPortDisconnectedFunction;
	var oldPCSCInitializationCallback;

	/*
	 * Create a handler for starting the application UI
	 */
	chrome.app.runtime.onLaunched.addListener(function() {
		chrome.app.window.create('ui.html', {
			"id": "cackeyUI",
			"focused": true,
			"innerBounds": {
				"width": 350,
				"minWidth": 350,
				"height": 135,
				"minHeight": 135
			}
		}, function(uiWindow) {
			if (!uiWindow) {
				return;
			}

			uiWindow.contentWindow.parentWindow = window;
		});
	});

	/*
	 * Register a handler for dealing with the PCSC port being disconnected
	 */
	oldOnPortDisconnectedFunction = GoogleSmartCard.Pcsc.prototype.onPortDisconnected_;
	GoogleSmartCard.Pcsc.prototype.onPortDisconnected_ = function() {
		oldOnPortDisconnectedFunction.apply(this);

		cackeyRestart();

		return;
	};

	/*
	 * Register a handler for dealing with the PCSC port being available
	 */
	oldPCSCInitializationCallback = GoogleSmartCard.PcscNacl.prototype.pcscInitializationCallback_;
	GoogleSmartCard.PcscNacl.prototype.pcscInitializationCallback_ = function(requestId, instanceId, instance, error) {
		oldPCSCInitializationCallback.apply(this, [requestId, instanceId, instance, error]);

		return;
	};

	/*
	 * Initialize global state
	 */
	cackeyInitGlobalState();

	return;
}

/* Initialize CACKey */
cackeyAppInit();
cackeyInit();
