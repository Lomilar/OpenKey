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
		globalCerts = certs;

		displayCerts(htmlObject, certs);
	});

	return;
}

setTimeout(function() {
	updateCertificates(document.getElementById('certificates'));
}, 1);
