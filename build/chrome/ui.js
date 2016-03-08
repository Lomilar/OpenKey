var globalCerts = null;

function displayCerts(htmlObject, certs) {
	var html = "";
	var idx;
	var cert;
	var certObj;

	if (certs.length == 0) {
		htmlObject.innerHTML = "<b>No certificates found</b>";

		return;
	}

	certObj = new X509;

	html += "<ol type=\"1\">";

	for (idx = 0; idx < certs.length; idx++) {
		cert = certs[idx];

		certObj.hex = BAtohex(new Uint8Array(cert.certificate));

		html += "\t<li>";
		html += "\t\t" + certObj.getSubjectString() + ":" + certObj.getSerialNumberHex();
		html += "\t\t<ol type=\"a\">";
		html += "\t\t\t<li>Serial Number: " + certObj.getSerialNumberHex() + "</li>";
		html += "\t\t\t<li>Usage: " + X509.getExtKeyUsageString(certObj.hex) + "</li>";
		html += "\t\t</ol>";
		html += "\t</li>";
	}

	html += "</ol>";

	delete certObj;

	htmlObject.innerHTML = html;
}
function updateCertificates(htmlObject) {
	var html = "";

	if (globalCerts == null) {
		htmlObject.innerHTML = "<i>Updating...</i>";
	} else {
		displayCerts(htmlObject, globalCerts);
	}

	parentWindow.cackeyListCertificates(function(certs) {
		/*
		 * If there is an error then we are invoked with no certs
		 * parameter at all, fake one.
		 */
		if (!certs) {
			certs = [];
		}

		globalCerts = certs;

		displayCerts(htmlObject, certs);
	});

	return;
}

function updateCertificateProvider(htmlObject) {
	var resultHTML;

	if (chrome.certificateProvider) {
		resultHTML = "Yes (ChromeOS)";
	} else {
		resultHTML = "<b>No, informational only.</b>";
	}

	htmlObject.innerHTML = resultHTML;

	return;
}

setTimeout(function() {
	updateCertificates(document.getElementById('certificates'));
	updateCertificateProvider(document.getElementById('certificate_provider'));
}, 1);
