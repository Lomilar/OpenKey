#include <stdio.h>

#include "cackey-chrome.h"

int main(int argc, char **argv) {
	struct cackey_certificate *certificates;
	int numCertificates;

	numCertificates = cackey_chrome_listCertificates(&certificates);

	printf("numCertificates = %i\n", numCertificates);

	return(0);
}
