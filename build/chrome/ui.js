var globalCerts = null;

function displayCerts(htmlObject, certs) {
	var html = "";
	var idx;
	var cert;
	var certObj;

	certObj = new X509;

	html += "<ol>";

	for (idx = 0; idx < certs.length; idx++) {
		cert = certs[idx];

		certObj.hex = BAtohex(new Uint8Array(cert.certificate));

		html += "\t<li>" + certObj.getSubjectString() + "</li>";
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
