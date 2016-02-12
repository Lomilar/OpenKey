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

/*
 * Handle and ID for outstanding callbacks
 */
var cackeyOutstandingCallbacks = []
var cackeyOutstandingCallbackCounter = -1;

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
				supportedHashes: ['SHA1', 'SHA256']
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
}

/*
 * Handle a response from the NaCl side regarding signing a message
 */
function cackeyMessageIncomingSignMessage(message, chromeCallback) {
	var payload;

	payload = message.signedData;

	chromeCallback(payload);
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

	console.log("START MESSAGE");
	console.log(messageEvent.data);
	console.log("END MESSAGE");

	chromeCallback = cackeyOutstandingCallbacks[messageEvent.data.id];

	if (chromeCallback == null) {
		console.log("[cackey] Discarding outdated message");

		return;
	}

	if (messageEvent.data.status != "success") {
		console.error("[cackey] Failed to execute command '" + messageEvent.data.command + "': " + messageEvent.data.error);

		chromeCallback();
	} else {
		switch (messageEvent.data.command) {
			case "listcertificates":
				nextFunction = cackeyMessageIncomingListCertificates;

				break;
			case "sign":
				nextFunction = cackeyMessageIncomingSignMessage;

				break;
		}
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

	console.log("[cackey] Asked to provide a list of certificates -- throwing that request over to the NaCl side... ");

	callbackId = cackeyOutstandingCallbackCounter + 1;

	cackeyHandle.postMessage(
		{
			'target': "cackey",
			'command': "listcertificates",
			'id': callbackId
		}
	);

	cackeyOutstandingCallbackCounter = callbackId;
	cackeyOutstandingCallbacks[callbackId] = chromeCallback;

	console.log("[cackey] Thrown.");

	return;
}

/*
 * Handler for messages from Chrome related to signing a hash of some sort
 */
function cackeySignMessage(signRequest, chromeCallback) {
	var callbackId;

	console.log("[cackey] Asked to sign a message -- throwing that request over to the NaCl side... ");

	callbackId = cackeyOutstandingCallbackCounter + 1;

	cackeyHandle.postMessage(
		{
			'target': "cackey",
			'command': "sign",
			'id': callbackId,
			'certificate': signRequest.certificate,
			'data': signRequest.digest /* XXX:TODO: This needs to be prefixed based on the signRequest.hash */
		}
	);

	cackeyOutstandingCallbackCounter = callbackId;
	cackeyOutstandingCallbacks[callbackId] = chromeCallback;

	console.log("[cackey] Thrown.");

	return;
}

/*
 * Finish performing initialization that must wait until we have loaded the CACKey module
 */
function cackeyInitLoaded(messageEvent) {
	console.log("[cackey] Loaded CACKey PNaCl Module");

	/* Register listeners with Chrome */
	if (chrome.certificateProvider) {
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

	/* Log that we are operational */
	console.log("[cackey] cackeyInit(): Called.");

	/* Verify that we can register callbacks */
	if (!chrome.certificateProvider) {
		if (!GoogleSmartCard.IS_DEBUG_BUILD) {
			console.error("[cackey] This extension only works on ChromeOS!");

			return;
		} else {
			console.log("[cackey] This extension only works on ChromeOS, but you appear to be debugging it -- trying anyway.");
		}
	}

	if (cackeyHandle != null) {
		console.log("[cackey] cackeyInit(): Already initialized.  Returning.");

		return;
	}

	elementEmbed = document.createElement('embed');
	elementEmbed.type = "application/x-pnacl";
	elementEmbed.width = 0;
	elementEmbed.height = 0;
	elementEmbed.src = "cackey.nmf";
	elementEmbed.id = "cackeyModule";
	elementEmbed.addEventListener('error', function(messageEvent) { console.error("Error loading CACKey PNaCl Module: " + messageEvent.data); }, true);
	elementEmbed.addEventListener('load', cackeyInitLoaded, true);
	elementEmbed.addEventListener('message', cackeyMessageIncoming, true);

	cackeyHandle = elementEmbed;

	/*
	 * Start the Google PCSC Interface
	 */
	new GoogleSmartCard.PcscNacl(cackeyHandle);

	document.body.appendChild(cackeyHandle)

	console.log("[cackey] cackeyInit(): Completed.  Returning.");
}

/* Initialize CACKey */
cackeyInit();
