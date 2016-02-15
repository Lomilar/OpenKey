#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "cackey-chrome.h"

int main(int argc, char **argv) {
	struct cackey_certificate *certificates;
	char *pinPrompt = NULL, pin[32];
	unsigned char signBuffer[1024];
	int numCertificates, idxCertificate;
	unsigned long signLength;
	cackey_chrome_returnType rvSign;

	numCertificates = cackey_chrome_listCertificates(&certificates);

	printf("numCertificates = %i\n", numCertificates);

	for (idxCertificate = 0; idxCertificate < numCertificates; idxCertificate++) {
		printf("Certificate #%i: %lu bytes\n", idxCertificate, certificates[idxCertificate].certificate_len);

		signLength = sizeof(signBuffer);
		rvSign = cackey_chrome_signMessage(&certificates[idxCertificate], "Test", 4, signBuffer, &signLength, &pinPrompt, NULL);

		if (rvSign == CACKEY_CHROME_NEEDLOGIN) {
			if (pinPrompt == NULL) {
				pinPrompt = strdup("Please enter your PIN: ");
			}

			printf("%s: ", pinPrompt);
			fflush(stdout);

			free(pinPrompt);

			pinPrompt = NULL;

			fgets(pin, sizeof(pin), stdin);
			while (strlen(pin) >= 1 && pin[strlen(pin) - 1] == '\n') {
				pin[strlen(pin) - 1] = '\0';
			}

			signLength = sizeof(signBuffer);
			rvSign = cackey_chrome_signMessage(&certificates[idxCertificate], "Test", 4, signBuffer, &signLength, &pinPrompt, pin);
		}

		if (pinPrompt != NULL) {
			free(pinPrompt);
		}

		printf("Signed message \"Test\": %lu bytes (return value = %i)\n", signLength, rvSign);
	}

	cackey_chrome_freeCertificates(certificates, numCertificates);

	cackey_chrome_terminate();

	return(0);
}
