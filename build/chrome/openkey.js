
/*
 * Handler for messages from Chrome related to decrypting a message of some sort
 */
function cackeyDecryptMessage(signRequest, chromeCallback) {
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

	if (goog.DEBUG) {
		console.log("[cackey] Asked to sign a message -- throwing that request over to the NaCl side... ");
	}

	callbackId = ++cackeyOutstandingCallbackCounter;

	command = {
		'target': "openkey",
		'command': "decrypt",
		'id': callbackId,
		'certificate': signRequest.certificate,
		'data': digest.buffer
	};

	certificateId = cackeyCertificateToPINID(command.certificate);

	if (cackeyCertificateToPINMap[certificateId] && cackeyCertificateToPINMap[certificateId].pin) {
		command.pin = cackeyCertificateToPINMap[certificateId].pin;

		cackeyCertificateToPINMapUpdateLastUsed(certificateId);
	}

	cackeyInitPCSC(function() {
		cackeyHandle.postMessage(command);

		cackeyOutstandingCallbacks[callbackId] = chromeCallback;

		if (goog.DEBUG) {
			console.log("[cackey] Thrown.");
		}
	}, chromeCallback);

	return;
}
