#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <stdlib.h>

#include "mypkcs11.h"
#include "cackey-chrome.h"

struct cackey_chrome_id {
	unsigned char *id;
	size_t idLen;
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
	CK_ATTRIBUTE attrTemplate[] = {
		{CKA_ID, NULL, 0}
	}, *currAttr;
	CK_ULONG currAttrIndex;
	CK_OBJECT_CLASS objectClassPrivateKey = CKO_PRIVATE_KEY;

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
		return(0);
	}

	searchTemplatePrivateKeys[0].pValue = &objectClassPrivateKey;

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

			for (currAttrIndex = 0; currAttrIndex < (sizeof(attrTemplate) / sizeof(attrTemplate[0])); currAttrIndex++) {
				currAttr = &attrTemplate[currAttrIndex];

				currAttr->pValue = NULL;
				currAttr->ulValueLen = 0;
			}

			chk_rv = C_GetAttributeValue(hSession, hObject, attrTemplate, sizeof(attrTemplate) / sizeof(attrTemplate[0]));
			if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
				chk_rv = CKR_OK;
			}

			if (chk_rv != CKR_OK) {
				continue;
			}

			for (currAttrIndex = 0; currAttrIndex < (sizeof(attrTemplate) / sizeof(attrTemplate[0])); currAttrIndex++) {
				currAttr = &attrTemplate[currAttrIndex];

				if (currAttr->ulValueLen == 0) {
					continue;
				}

				if (((CK_LONG) currAttr->ulValueLen) == ((CK_LONG) -1)) {
					continue;
				}

				currAttr->pValue = malloc(currAttr->ulValueLen);
			}

			chk_rv = C_GetAttributeValue(hSession, hObject, attrTemplate, sizeof(attrTemplate) / sizeof(attrTemplate[0]));
			if (chk_rv != CKR_OK) {
				continue;
			}

		}

		moduleFunctionList->C_FindObjectsFinal(hSession);

		moduleFunctionList->C_CloseSession(hSession);
	}

	return(0);
}

#ifdef __cplusplus
}
#endif
