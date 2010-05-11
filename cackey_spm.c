/*
 * GSC-IS (v2.1) Service Call Level Service Provider Module for PC/SC Lite and
 * DoD CAC/CACv2/PIV/PIVv2 Cards
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cackey_spm.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif

unsigned long gscBsiUtilAcquireContext(unsigned long hCard, unsigned char *AID, struct BSIAuthenticator strctAuthenticator[], unsigned long authNb) {
}

unsigned long gscBsiUtilConnect(unsigned char *readerName, unsigned long *hCard) {
}

unsigned long gscBsiUtilDisconnect(unsigned long hCard) {
}

unsigned long gscBsiUtilBeginTransaction(unsigned long hCard, _Bool blType) {
}

unsigned long gscBsiUtilEndTransaction(unsigned long hCard) {
}

unsigned long gscBsiUtilGetVersion(unsigned char **version) {
	int sprintf_ret;

	if (version == NULL) {
		return(BSI_UNKNOWN_ERROR);
	}

	if (*version == NULL) {
		sprintf_ret = sprintf(NULL, "2,1,0,%s", PACKAGE_VERSION);

		if (sprintf_ret <= 0) {
			return(BSI_UNKNOWN_ERROR);
		}

		*version = malloc(sprintf_ret + 1);
	}

	/* Hopefully their buffer is large enough ... */
	sprintf(*version, "2,1,0,%s", PACKAGE_VERSION);

	return(BSI_OK);
}

unsigned long gscBsiUtilGetCardProperties(unsigned long hCard, unsigned char **CCCUniqueID, unsigned long *cardCapability) {
}

unsigned long gscBsiUtilGetCardStatus(unsigned long hCard) {
}

unsigned long gscBsiUtilGetExtendedErrorText(unsigned long hCard, unsigned char **errorText) {
	if (errorText == NULL) {
		return(BSI_UNKNOWN_ERROR);
	}

	*errorText = NULL;

	return(BSI_NO_TEXT_AVAILABLE);
}

unsigned long gscBsiUtilGetReaderList(unsigned char ***readerList) {
}

unsigned long gscBsiUtilPassthru(unsigned long hCard, unsigned char *cardCommand, unsigned char **cardResponse) {
}

unsigned long gscBsiUtilReleaseContext(unsigned long hCard, unsigned char *AID) {
}

unsigned long gscBsiGcDataCreate(unsigned long hCard, unsigned char *AID, unsigned char tag, unsigned char *value) {
}

unsigned long gscBsiGcDataDelete(unsigned long hCard, unsigned char *AID, unsigned char tag) {
}

unsigned long gscBsiGcGetContainerProperties(unsigned long hCard, unsigned char *AID, struct GCacr *strctGCacr, struct GCContainerSize *strctContainerSizes, unsigned char **containerVersion) {
}

unsigned long gscBsiGcReadTagList(unsigned long hCard, unsigned char *AID, unsigned char **tagArray) {
}

unsigned long gscBsiGcReadValue(unsigned long hCard, unsigned char *AID, unsigned char tag, unsigned char **value) {
}

unsigned long gscBsiGcUpdateValue(unsigned long hCard, unsigned char *AID, unsigned char tag, unsigned char *value) {
}

unsigned long gscBsiGetChallenge(unsigned long hCard, unsigned char *AID, unsigned char **challenge) {
}

unsigned long gscBsiSkiInternalAuthenticate(unsigned long hCard, unsigned char *AID, unsigned char algoID, unsigned char *challenge, unsigned char **cryptogram) {
}

unsigned long gscBsiPkiCompute(unsigned long hCard, unsigned char *AID, unsigned char algoID, unsigned char *message, unsigned char **result) {
}

unsigned long gscBsiPkiGetCertificate(unsigned long hCard, unsigned char *AID, unsigned char **Certificate) {
}

unsigned long gscBsiGetCryptoProperties(unsigned long hCard, unsigned char *AID, struct CRYPTOacr *strctCRYPTOacr, unsigned long *keyLen) {
}
