#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "mypkcs11.h"
#include "cackey-chrome.h"

struct cackey_chrome_id {
	void *id;
	size_t idLen;
	int initialized;
};

static CK_FUNCTION_LIST_PTR moduleFunctionList = NULL;

static CK_RV cackey_chrome_init(void) {
	CK_C_INITIALIZE_ARGS initargs;
	CK_RV chk_rv;

	if (moduleFunctionList != NULL) {
		return(CKR_OK);
	}

	chk_rv = C_GetFunctionList(&moduleFunctionList);
	if (chk_rv != CKR_OK) {
		return(chk_rv);
	}

	initargs.CreateMutex = NULL;
	initargs.DestroyMutex = NULL;
	initargs.LockMutex = NULL;
	initargs.UnlockMutex = NULL;
	initargs.flags = CKF_OS_LOCKING_OK;
	initargs.pReserved = NULL;

	chk_rv = moduleFunctionList->C_Initialize(&initargs);
	if (chk_rv != CKR_OK) {
		return(chk_rv);
	}

	return(CKR_OK);
}

void cackey_chrome_terminate(void) {
	if (!moduleFunctionList) {
		return;
	}

	moduleFunctionList->C_Finalize(NULL);

	free(moduleFunctionList);

	moduleFunctionList = NULL;

	return;
}

static CK_RV cackey_chrome_GetAttributesFromTemplate(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE *attrTemplate, CK_ULONG attrTemplateCount) {
	CK_RV chk_rv;
 	CK_ATTRIBUTE *currAttr;
	CK_ULONG currAttrIndex;

	for (currAttrIndex = 0; currAttrIndex < attrTemplateCount; currAttrIndex++) {
		currAttr = &attrTemplate[currAttrIndex];

		currAttr->pValue = NULL;
		currAttr->ulValueLen = 0;
	}

	chk_rv = moduleFunctionList->C_GetAttributeValue(hSession, hObject, attrTemplate, attrTemplateCount);
	if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
		chk_rv = CKR_OK;
	}

	if (chk_rv != CKR_OK) {
		return(chk_rv);
	}

	for (currAttrIndex = 0; currAttrIndex < attrTemplateCount; currAttrIndex++) {
		currAttr = &attrTemplate[currAttrIndex];

		if (currAttr->ulValueLen == 0) {
			continue;
		}

		if (((CK_LONG) currAttr->ulValueLen) == ((CK_LONG) -1)) {
			continue;
		}

		currAttr->pValue = malloc(currAttr->ulValueLen);
	}

	chk_rv = moduleFunctionList->C_GetAttributeValue(hSession, hObject, attrTemplate, attrTemplateCount);
	if (chk_rv != CKR_OK) {
		free(currAttr->pValue);

		return(chk_rv);
	}

	return(CKR_OK);
}

int cackey_chrome_listCertificates(struct cackey_certificate **certificates) {
	CK_RV chk_rv;
	CK_ULONG numSlots, currSlot;
	CK_SLOT_ID_PTR slots;
	CK_SLOT_INFO slotInfo;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG ulObjectCount;
	CK_ATTRIBUTE searchTemplatePrivateKeys[] = {
		{CKA_CLASS, NULL, sizeof(CK_OBJECT_CLASS)}
	};
	CK_ATTRIBUTE searchTemplateCertificates[] = {
		{CKA_CLASS, NULL, sizeof(CK_OBJECT_CLASS)},
		{CKA_ID, NULL, 0}
	};
	CK_ATTRIBUTE attrTemplatePrivateKey[] = {
		{CKA_ID, NULL, 0}
	};
	CK_ATTRIBUTE attrTemplateCertificate[] = {
		{CKA_VALUE, NULL, 0}
	};
	CK_OBJECT_CLASS objectClassPrivateKey = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS objectClassCertificate = CKO_CERTIFICATE;
	struct cackey_chrome_id *ids;
	int idsCount, currId;
	int foundCertificates, certificatesCount;

	*certificates = NULL;

	chk_rv = cackey_chrome_init();
	if (chk_rv != CKR_OK) {
		return(0);
	}

	chk_rv = moduleFunctionList->C_GetSlotList(FALSE, NULL, &numSlots);
	if (chk_rv != CKR_OK) {
		return(0);
	}

	slots = malloc(sizeof(*slots) * numSlots);

	chk_rv = moduleFunctionList->C_GetSlotList(FALSE, slots, &numSlots);
	if (chk_rv != CKR_OK) {
		free(slots);

		return(0);
	}

	searchTemplatePrivateKeys[0].pValue = &objectClassPrivateKey;
	searchTemplateCertificates[0].pValue = &objectClassCertificate;

	foundCertificates = 0;
	certificatesCount = 10;
	*certificates = malloc(sizeof(**certificates) * certificatesCount);

	idsCount = 10;
	ids = malloc(sizeof(*ids) * idsCount);

	for (currId = 0; currId < idsCount; currId++) {
		ids[currId].initialized = 0;
	}

	for (currSlot = 0; currSlot < numSlots; currSlot++) {
		chk_rv = moduleFunctionList->C_GetSlotInfo(slots[currSlot], &slotInfo);
		if (chk_rv != CKR_OK) {
			continue;
		}

		if ((slotInfo.flags & CKF_TOKEN_PRESENT) != CKF_TOKEN_PRESENT) {
			continue;
		}

		chk_rv = moduleFunctionList->C_OpenSession(slots[currSlot], CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		if (chk_rv != CKR_OK) {
			continue;
		}

		chk_rv = moduleFunctionList->C_FindObjectsInit(hSession, searchTemplatePrivateKeys, sizeof(searchTemplatePrivateKeys) / sizeof(searchTemplatePrivateKeys[0])); 
		if (chk_rv != CKR_OK) {
			moduleFunctionList->C_CloseSession(hSession);

			continue;
		}

		for (currId = 0; currId < idsCount; currId++) {
			if (!ids[currId].initialized) {
				continue;
			}

			free(ids[currId].id);

			ids[currId].initialized = 0;
		}

		currId = 0;

		while (1) {
			chk_rv = moduleFunctionList->C_FindObjects(hSession, &hObject, 1, &ulObjectCount);
			if (chk_rv != CKR_OK) {
				break;
			}

			if (ulObjectCount == 0) {
				break;
			}

			if (ulObjectCount != 1) {
				break;
			}

			chk_rv = cackey_chrome_GetAttributesFromTemplate(hSession, hObject, attrTemplatePrivateKey, sizeof(attrTemplatePrivateKey) / sizeof(attrTemplatePrivateKey[0]));
			if (chk_rv != CKR_OK) {
				continue;
			}

			if (currId >= idsCount) {
				idsCount *= 2;

				ids = realloc(ids, sizeof(*ids) * idsCount);
			}

			ids[currId].idLen = attrTemplatePrivateKey[0].ulValueLen;
			ids[currId].id = attrTemplatePrivateKey[0].pValue;
			ids[currId].initialized = 1;
			currId++;
		}

		moduleFunctionList->C_FindObjectsFinal(hSession);

		for (currId = 0; currId < idsCount; currId++) {
			if (!ids[currId].initialized) {
				continue;
			}

			searchTemplateCertificates[1].pValue = ids[currId].id;
			searchTemplateCertificates[1].ulValueLen = ids[currId].idLen;

			chk_rv = moduleFunctionList->C_FindObjectsInit(hSession, searchTemplateCertificates, sizeof(searchTemplateCertificates) / sizeof(searchTemplateCertificates[0])); 
			if (chk_rv != CKR_OK) {
				free(ids[currId].id);

				ids[currId].initialized = 0;

				continue;
			}

			while (1) {
				chk_rv = moduleFunctionList->C_FindObjects(hSession, &hObject, 1, &ulObjectCount);
				if (chk_rv != CKR_OK) {
					break;
				}

				if (ulObjectCount == 0) {
					break;
				}

				if (ulObjectCount != 1) {
					break;
				}

				chk_rv = cackey_chrome_GetAttributesFromTemplate(hSession, hObject, attrTemplateCertificate, sizeof(attrTemplateCertificate) / sizeof(attrTemplateCertificate[0]));
				if (chk_rv != CKR_OK) {
					continue;
				}

				if (foundCertificates >= certificatesCount) {
					certificatesCount *= 2;
					*certificates = realloc(*certificates, sizeof(**certificates) * certificatesCount);
				}

				(*certificates)[foundCertificates].certificate = malloc(attrTemplateCertificate[0].ulValueLen);
				memcpy((*certificates)[foundCertificates].certificate, attrTemplateCertificate[0].pValue, attrTemplateCertificate[0].ulValueLen);
				(*certificates)[foundCertificates].certificate_len = attrTemplateCertificate[0].ulValueLen;

				free(attrTemplateCertificate[0].pValue);

				foundCertificates++;
			}

			moduleFunctionList->C_FindObjectsFinal(hSession);

			free(ids[currId].id);

			ids[currId].initialized = 0;
		}

		moduleFunctionList->C_CloseSession(hSession);
	}

	for (currId = 0; currId < idsCount; currId++) {
		if (!ids[currId].initialized) {
			continue;
		}

		free(ids[currId].id);

		ids[currId].initialized = 0;
	}

	free(ids);

	free(slots);

	return(foundCertificates);
}

void cackey_chrome_freeCertificates(struct cackey_certificate *certificates, int certificatesCount) {
	int idx;

	if (certificates == NULL) {
		return;
	}

	for (idx = 0; idx < certificatesCount; idx++) {
		if (certificates[idx].certificate) {
			free(certificates[idx].certificate);
		}
	}

	free(certificates);

	return;
}

cackey_chrome_returnType cackey_chrome_signMessage(struct cackey_certificate *certificate, void *data, unsigned long dataLength, unsigned char *destination, unsigned long *destinationLength, char **pinPrompt, char *pin) {
	CK_RV chk_rv;
	CK_ULONG numSlots, currSlot;
	CK_SLOT_ID_PTR slots;
	CK_SLOT_INFO slotInfo;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject, hKey;
	CK_ULONG ulObjectCount;
	CK_ATTRIBUTE searchTemplateCertificates[] = {
		{CKA_CLASS, NULL, sizeof(CK_OBJECT_CLASS)},
		{CKA_VALUE, NULL, 0}
	};
	CK_ATTRIBUTE searchTemplatePrivateKeys[] = {
		{CKA_CLASS, NULL, sizeof(CK_OBJECT_CLASS)},
		{CKA_ID, NULL, 0}
	};
	CK_ATTRIBUTE attrTemplateCertificate[] = {
		{CKA_ID, NULL, 0},
		{CKA_LABEL, NULL, 0}
	};
	CK_MECHANISM signMechanism = {CKM_RSA_PKCS, NULL, 0}; 
	CK_OBJECT_CLASS objectClassPrivateKey = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS objectClassCertificate = CKO_CERTIFICATE;
	CK_TOKEN_INFO tokenInfo;
	CK_ULONG tmpDestinationLength;
	char *certificateLabel;
	int foundPrivateKeyObject;
	cackey_chrome_returnType retval;

	*pinPrompt = NULL;

	retval = CACKEY_CHROME_ERROR;

	chk_rv = cackey_chrome_init();
	if (chk_rv != CKR_OK) {
		return(retval);
	}

	chk_rv = moduleFunctionList->C_GetSlotList(FALSE, NULL, &numSlots);
	if (chk_rv != CKR_OK) {
		return(retval);
	}

	slots = malloc(sizeof(*slots) * numSlots);

	chk_rv = moduleFunctionList->C_GetSlotList(FALSE, slots, &numSlots);
	if (chk_rv != CKR_OK) {
		free(slots);

		return(retval);
	}

	searchTemplateCertificates[0].pValue = &objectClassCertificate;
	searchTemplatePrivateKeys[0].pValue = &objectClassPrivateKey;

	searchTemplateCertificates[1].pValue = certificate->certificate;
	searchTemplateCertificates[1].ulValueLen = certificate->certificate_len;

	foundPrivateKeyObject = 0;

	certificateLabel = NULL;

	for (currSlot = 0; currSlot < numSlots; currSlot++) {
		chk_rv = moduleFunctionList->C_GetSlotInfo(slots[currSlot], &slotInfo);
		if (chk_rv != CKR_OK) {
			continue;
		}

		if ((slotInfo.flags & CKF_TOKEN_PRESENT) != CKF_TOKEN_PRESENT) {
			continue;
		}

		chk_rv = moduleFunctionList->C_OpenSession(slots[currSlot], CKF_SERIAL_SESSION, NULL, NULL, &hSession);
		if (chk_rv != CKR_OK) {
			continue;
		}

		chk_rv = moduleFunctionList->C_FindObjectsInit(hSession, searchTemplateCertificates, sizeof(searchTemplateCertificates) / sizeof(searchTemplateCertificates[0])); 
		if (chk_rv != CKR_OK) {
			moduleFunctionList->C_CloseSession(hSession);

			continue;
		}

		while (1) {
			chk_rv = moduleFunctionList->C_FindObjects(hSession, &hObject, 1, &ulObjectCount);
			if (chk_rv != CKR_OK) {
				break;
			}

			if (ulObjectCount == 0) {
				break;
			}

			if (ulObjectCount != 1) {
				break;
			}

			chk_rv = cackey_chrome_GetAttributesFromTemplate(hSession, hObject, attrTemplateCertificate, sizeof(attrTemplateCertificate) / sizeof(attrTemplateCertificate[0]));
			if (chk_rv != CKR_OK) {
				continue;
			}

			searchTemplatePrivateKeys[1].pValue = attrTemplateCertificate[0].pValue;
			searchTemplatePrivateKeys[1].ulValueLen = attrTemplateCertificate[0].ulValueLen;

			if (attrTemplateCertificate[1].ulValueLen > 0 && attrTemplateCertificate[1].pValue != NULL) {
				certificateLabel = malloc(attrTemplateCertificate[1].ulValueLen + 1);
				memcpy(certificateLabel, attrTemplateCertificate[1].pValue, attrTemplateCertificate[1].ulValueLen);
				certificateLabel[attrTemplateCertificate[1].ulValueLen] = '\0';
			}

			break;
		}

		moduleFunctionList->C_FindObjectsFinal(hSession);

		if (searchTemplatePrivateKeys[1].pValue != NULL) {
			chk_rv = moduleFunctionList->C_FindObjectsInit(hSession, searchTemplateCertificates, sizeof(searchTemplateCertificates) / sizeof(searchTemplateCertificates[0])); 
			if (chk_rv == CKR_OK) {
				while (1) {
					chk_rv = moduleFunctionList->C_FindObjects(hSession, &hObject, 1, &ulObjectCount);
					if (chk_rv != CKR_OK) {
						break;
					}

					if (ulObjectCount == 0) {
						break;
					}

					if (ulObjectCount != 1) {
						break;
					}

					hKey = hObject;

					foundPrivateKeyObject = 1;

					break;
				}

				moduleFunctionList->C_FindObjectsFinal(hSession);
			}

			free(searchTemplatePrivateKeys[1].pValue);

		}

		if (foundPrivateKeyObject) {
			chk_rv = moduleFunctionList->C_SignInit(hSession, &signMechanism, hKey);
			if (chk_rv != CKR_OK) {
				break;
			}

			tmpDestinationLength = *destinationLength;
			chk_rv = moduleFunctionList->C_Sign(hSession, data, dataLength, destination, &tmpDestinationLength);
			switch (chk_rv) {
				case CKR_OK:
					*destinationLength = tmpDestinationLength;
					retval = CACKEY_CHROME_OK;
					break;
				case CKR_USER_NOT_LOGGED_IN:
					chk_rv = moduleFunctionList->C_GetTokenInfo(slots[currSlot], &tokenInfo);
					if (chk_rv == CKR_OK) {
						if ((tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) == CKF_PROTECTED_AUTHENTICATION_PATH) {
							retval = CACKEY_CHROME_NEEDPROTECTEDLOGIN;
						} else {
							retval = CACKEY_CHROME_NEEDLOGIN;

							*pinPrompt = malloc(1024);
							if (certificateLabel) {
								snprintf(*pinPrompt, 1024, "Please enter the PIN for %s:%s", tokenInfo.label, certificateLabel);
							} else {
								snprintf(*pinPrompt, 1024, "Please enter the PIN for %s", tokenInfo.label);
							}
						}
					} else {
						retval = CACKEY_CHROME_NEEDLOGIN;

						*pinPrompt = strdup("Please enter your Smartcard PIN");
					}

					if (retval == CACKEY_CHROME_NEEDPROTECTEDLOGIN) {
						retval = CACKEY_CHROME_ERROR;

						chk_rv = moduleFunctionList->C_Login(hSession, CKU_USER, NULL, 0);
					} else {
						if (pin) {
							retval = CACKEY_CHROME_ERROR;

							free(*pinPrompt);
							*pinPrompt = NULL;

							chk_rv = moduleFunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR) pin, strlen(pin));
						} else {
							chk_rv = CKR_GENERAL_ERROR;
						}
					}

					if (chk_rv == CKR_OK && retval == CACKEY_CHROME_ERROR) {
						chk_rv = moduleFunctionList->C_SignInit(hSession, &signMechanism, hKey);
						if (chk_rv != CKR_OK) {
							break;
						}

						tmpDestinationLength = *destinationLength;
						chk_rv = moduleFunctionList->C_Sign(hSession, data, dataLength, destination, &tmpDestinationLength);
						switch (chk_rv) {
							case CKR_OK:
								*destinationLength = tmpDestinationLength;
								retval = CACKEY_CHROME_OK;
								break;
							case CKR_USER_NOT_LOGGED_IN:
								retval = CACKEY_CHROME_NEEDLOGIN;
								break;
							default:
								retval = CACKEY_CHROME_ERROR;
								break;
						}
					}

					break;
				default:
					retval = CACKEY_CHROME_ERROR;
					break;
			}

			break;
		}

		moduleFunctionList->C_CloseSession(hSession);
	}

	free(slots);

	if (certificateLabel) {
		free(certificateLabel);
	}

	return(retval);
}

#ifdef __cplusplus
}
#endif
