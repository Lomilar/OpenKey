/*
 * CACKey ChromeOS chrome.certificateProvider Implementation
 */

function onCertificatesRejected(rejectedCerts) {
	// If certificates were rejected by the API, log an error, for example.
	console.error(rejectedCerts.length + ' certificates were rejected.');
	return;
}

function cackeyListCertificates(chromeCallback) {
	var certificates = [];

	certificates.push(
		{
			certificate: new UInt8Array(),
			supportedHashes: ['SHA1', 'SHA256']
		}
	);

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

function cackeySignMessage(signRequest, chromeCallback) {
	/* XXX:TODO: Implement this */
	chromeCallback();

	return;
}

/* Register listeners with Chrome */
chrome.certificateProvider.onCertificatesRequested.addListener(cackeyListCertificates);
chrome.certificateProvider.onSignDigestRequested.addListener(cackeySignMessage);
