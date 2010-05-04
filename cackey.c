#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_PCSCLITE_H
#  include <pcsclite.h>
#endif
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#ifdef HAVE_PTHREAD_H
#  include <pthread.h>
#endif

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#  define NULL_PTR 0
#endif

#include "pkcs11.h"

#ifndef CACKEY_CRYPTOKI_VERSION_CODE
#  define CACKEY_CRYPTOKI_VERSION_CODE 0x021e00
#endif

#ifdef CACKEY_DEBUG
#  ifdef HAVE_STDIO_H
#    include <stdio.h>
#  endif

#  define CACKEY_DEBUG_PRINTF(x...) { fprintf(stderr, "%s(): ", __func__); fprintf(stderr, x); fprintf(stderr, "\n"); }
#  define CACKEY_DEBUG_PRINTBUF(f, x, y) { unsigned char *buf; unsigned long idx; buf = (unsigned char *) (x); fprintf(stderr, "%s(): %s  (%s/%lu = {%02x", __func__, f, #x, (unsigned long) (y), buf[0]); for (idx = 1; idx < (y); idx++) { fprintf(stderr, ", %02x", buf[idx]); }; fprintf(stderr, "})\n"); }
#  define CACKEY_DEBUG_PERROR(x) { fprintf(stderr, "%s(): ", __func__); perror(x); }
#  define free(x) { CACKEY_DEBUG_PRINTF("FREE(%p) (%s)", x, #x); free(x); }

static void *CACKEY_DEBUG_FUNC_MALLOC(size_t size, const char *func) {
	void *retval;

	retval = malloc(size);

	fprintf(stderr, "%s(): ", func);
	fprintf(stderr, "MALLOC() = %p", retval);
	fprintf(stderr, "\n");

	return(retval);
}

static void *CACKEY_DEBUG_FUNC_REALLOC(void *ptr, size_t size, const char *func) {
	void *retval;

	retval = realloc(ptr, size);

	if (retval != ptr) {
		fprintf(stderr, "%s(): ", func);
		fprintf(stderr, "REALLOC(%p) = %p", ptr, retval);
		fprintf(stderr, "\n");
	}

	return(retval);
}

#  define malloc(x) CACKEY_DEBUG_FUNC_MALLOC(x, __func__)
#  define realloc(x, y) CACKEY_DEBUG_FUNC_REALLOC(x, y, __func__)
#else
#  define CACKEY_DEBUG_PRINTF(x...) /**/
#  define CACKEY_DEBUG_PRINTBUF(f, x, y) /**/
#  define CACKEY_DEBUG_PERROR(x) /**/
#endif

#ifndef CKA_TRUST_SERVER_AUTH
#  define CKA_TRUST_SERVER_AUTH 0xce536358
#endif
#ifndef CKA_TRUST_CLIENT_AUTH
#  define CKA_TRUST_CLIENT_AUTH 0xce536359
#endif
#ifndef CKA_TRUST_CODE_SIGNING
#  define CKA_TRUST_CODE_SIGNING 0xce53635a
#endif
#ifndef CKA_TRUST_EMAIL_PROTECTION
#  define CKA_TRUST_EMAIL_PROTECTION 0xce53635b
#endif

struct cackey_identity {
	CK_ATTRIBUTE *attributes;
	CK_ULONG attributes_count;
};

struct cackey_session {
	int active;

	CK_SLOT_ID slotID;
	CK_STATE state;
	CK_FLAGS flags;
	CK_ULONG ulDeviceError;
	CK_VOID_PTR pApplication;
	CK_NOTIFY Notify;

	struct cackey_identity *identities;
	unsigned long identities_count;

	int search_active;
	CK_ATTRIBUTE_PTR search_query;
	CK_ULONG search_query_count;
	unsigned long search_curr_id;

	int sign_active;
	CK_MECHANISM_TYPE sign_mechanism;
	CK_BYTE_PTR sign_buf;
	unsigned long sign_buflen;
	unsigned long sign_bufused;

	int decrypt_active;
	CK_MECHANISM_TYPE decrypt_mechanism;
	CK_VOID_PTR decrypt_mech_parm;
	CK_ULONG decrypt_mech_parmlen;
};

static void *cackey_biglock = NULL;
static struct cackey_session cackey_sessions[8];
static int cackey_initialized = 0;
static int cackey_biglock_init = 0;
CK_C_INITIALIZE_ARGS cackey_args;

static unsigned long cackey_getversion(void) {
	static unsigned long retval = 255;
	unsigned long major = 0;
	unsigned long minor = 0;
	char *major_str = NULL;
	char *minor_str = NULL;

	CACKEY_DEBUG_PRINTF("Called.");

	if (retval != 255) {
		CACKEY_DEBUG_PRINTF("Returning 0x%lx (cached).", retval);

		return(retval);
	}

	retval = 0;

#ifdef PACKAGE_VERSION
        major_str = PACKAGE_VERSION;
	if (major_str) {
	        major = strtoul(major_str, &minor_str, 10);

		if (minor_str) {
			minor = strtoul(minor_str + 1, NULL, 10);
		}
	}

	retval = (major << 16) | (minor << 8);
#endif

	CACKEY_DEBUG_PRINTF("Returning 0x%lx", retval);

	return(retval);
}

/* Returns 0 on success */
static int cackey_mutex_create(void **mutex) {
	pthread_mutex_t *pthread_mutex;
	int pthread_retval;
	CK_RV custom_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if ((cackey_args.flags & CKF_OS_LOCKING_OK) == CKF_OS_LOCKING_OK) {
		pthread_mutex = malloc(sizeof(*pthread_mutex));
		if (!pthread_mutex) {
			CACKEY_DEBUG_PRINTF("Failed to allocate memory.");

			return(-1);
		}

		pthread_retval = pthread_mutex_init(pthread_mutex, NULL);
		if (pthread_retval != 0) {
			CACKEY_DEBUG_PRINTF("pthread_mutex_init() returned error (%i).", pthread_retval);

			return(-1);
		}

		*mutex = pthread_mutex;
	} else {
		if (cackey_args.CreateMutex) {
			custom_retval = cackey_args.CreateMutex(mutex);

			if (custom_retval != CKR_OK) {
				CACKEY_DEBUG_PRINTF("cackey_args.CreateMutex() returned error (%li).", (long) custom_retval);

				return(-1);
			}
		}
	}

	CACKEY_DEBUG_PRINTF("Returning sucessfully (0)");

	return(0);
}

/* Returns 0 on success */
static int cackey_mutex_lock(void *mutex) {
	pthread_mutex_t *pthread_mutex;
	int pthread_retval;
	CK_RV custom_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if ((cackey_args.flags & CKF_OS_LOCKING_OK) == CKF_OS_LOCKING_OK) {
		pthread_mutex = mutex;

		pthread_retval = pthread_mutex_lock(pthread_mutex);
		if (pthread_retval != 0) {
			CACKEY_DEBUG_PRINTF("pthread_mutex_lock() returned error (%i).", pthread_retval);

			return(-1);
		}
	} else {
		if (cackey_args.LockMutex) {
			custom_retval = cackey_args.LockMutex(mutex);

			if (custom_retval != CKR_OK) {
				CACKEY_DEBUG_PRINTF("cackey_args.LockMutex() returned error (%li).", (long) custom_retval);

				return(-1);
			}
		}
	}

	CACKEY_DEBUG_PRINTF("Returning sucessfully (0)");

	return(0);
}

/* Returns 0 on success */
static int cackey_mutex_unlock(void *mutex) {
	pthread_mutex_t *pthread_mutex;
	int pthread_retval;
	CK_RV custom_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if ((cackey_args.flags & CKF_OS_LOCKING_OK) == CKF_OS_LOCKING_OK) {
		pthread_mutex = mutex;

		pthread_retval = pthread_mutex_unlock(pthread_mutex);
		if (pthread_retval != 0) {
			CACKEY_DEBUG_PRINTF("pthread_mutex_unlock() returned error (%i).", pthread_retval);

			return(-1);
		}
	} else {
		if (cackey_args.UnlockMutex) {
			custom_retval = cackey_args.UnlockMutex(mutex);

			if (custom_retval != CKR_OK) {
				CACKEY_DEBUG_PRINTF("cackey_args.UnlockMutex() returned error (%li).", (long) custom_retval);

				return(-1);
			}
		}
	}

	CACKEY_DEBUG_PRINTF("Returning sucessfully (0)");

	return(0);
}

static CK_ATTRIBUTE_PTR cackey_get_attributes(CK_OBJECT_CLASS objectclass, void *identity, unsigned long identity_num, CK_ULONG_PTR pulCount) {
	static CK_BBOOL ck_true = 1;
	static CK_BBOOL ck_false = 0;
	CK_ULONG numattrs = 0, retval_count;
	CK_ATTRIBUTE_TYPE curr_attr_type;
	CK_ATTRIBUTE curr_attr, *retval;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
	CK_OBJECT_CLASS ck_object_class;
	CK_CERTIFICATE_TYPE ck_certificate_type;
	CK_KEY_TYPE ck_key_type;
	CK_UTF8CHAR ucTmpBuf[1024];
	unsigned char certificate[16384];
	ssize_t getcert_ret, certificate_len = -1, x509_read_ret;
	int fd;
	int pValue_free;

	CACKEY_DEBUG_PRINTF("Called (objectClass = %lu, identity_num = %lu).", (unsigned long) objectclass, identity_num);

	if (objectclass != CKO_CERTIFICATE && objectclass != CKO_PUBLIC_KEY && objectclass != CKO_PRIVATE_KEY) {
		CACKEY_DEBUG_PRINTF("Returning 0 objects (NULL), invalid object class");

		return(NULL);
	}

	retval_count = 16;
	retval = malloc(retval_count * sizeof(*retval));

	/* XXX: Get Cert */
	certificate_len = -1;

	if (certificate_len == -1) {
		CACKEY_DEBUG_PRINTF("Returning 0 objects (NULL), this identity does not have an X.509 certificate associated with it and will not work");

		return(NULL);
	}

	for (curr_attr_type = 0; curr_attr_type < 0xce53635f; curr_attr_type++) {
		if (curr_attr_type == 0x800) {
			curr_attr_type = 0xce536300;
		}

		pValue_free = 0;
		pValue = NULL;
		ulValueLen = (CK_LONG) -1;

		switch (curr_attr_type) {
			case CKA_CLASS:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_CLASS (0x%08lx) ...", (unsigned long) curr_attr_type);

				ck_object_class = objectclass;

				pValue = &ck_object_class;
				ulValueLen = sizeof(ck_object_class);

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_OBJECT_CLASS *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_TOKEN:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_TOKEN (0x%08lx) ...", (unsigned long) curr_attr_type);

				pValue = &ck_true;
				ulValueLen = sizeof(ck_true);

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_BBOOL *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_MODIFIABLE:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_MODIFIABLE (0x%08lx) ...", (unsigned long) curr_attr_type);

				pValue = &ck_false;
				ulValueLen = sizeof(ck_false);

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_BBOOL *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_LABEL:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_LABEL (0x%08lx) ...", (unsigned long) curr_attr_type);

				/* XXX: Determine name */

				CACKEY_DEBUG_PRINTF(" ... returning %s (%p/%lu)", (char *) ((CK_UTF8CHAR *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_VALUE:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_VALUE (0x%08lx) ...", (unsigned long) curr_attr_type);

				switch (objectclass) {
					case CKO_PRIVATE_KEY:
						CACKEY_DEBUG_PRINTF(" ... but not getting it because we are a private key.");

						break;
					case CKO_PUBLIC_KEY:
						/* XXX: TODO */

						break;
					case CKO_CERTIFICATE:
						pValue = certificate;
						ulValueLen = certificate_len;

						break;
				}

				CACKEY_DEBUG_PRINTF(" ... returning %p/%lu", pValue, (unsigned long) ulValueLen);

				break;
			case CKA_ISSUER:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_ISSUER (0x%08lx) ...", (unsigned long) curr_attr_type);

				if (objectclass != CKO_CERTIFICATE) {
					CACKEY_DEBUG_PRINTF(" ... but not getting it because we are not a certificate.");

					break;
				}

				if (certificate_len >= 0) {
					x509_read_ret = x509_to_issuer(certificate, certificate_len, &pValue);
					if (x509_read_ret < 0) {
						pValue = NULL;
					} else {
						ulValueLen = x509_read_ret;
					}
				}

				CACKEY_DEBUG_PRINTF(" ... returning %p/%lu", pValue, (unsigned long) ulValueLen);

				break;
			case CKA_SERIAL_NUMBER:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_SERIAL_NUMBER (0x%08lx) ...", (unsigned long) curr_attr_type);

				if (objectclass != CKO_CERTIFICATE) {
					CACKEY_DEBUG_PRINTF(" ... but not getting it because we are not a certificate.");

					break;
				}

				if (certificate_len >= 0) {
					x509_read_ret = x509_to_serial(certificate, certificate_len, &pValue);
					if (x509_read_ret < 0) {
						pValue = NULL;
					} else {
						ulValueLen = x509_read_ret;
					}
				}

				CACKEY_DEBUG_PRINTF(" ... returning (%p/%lu)", pValue, (unsigned long) ulValueLen);

				break;
			case CKA_SUBJECT:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_SUBJECT (0x%08lx) ...", (unsigned long) curr_attr_type);

				if (objectclass != CKO_CERTIFICATE) {
					CACKEY_DEBUG_PRINTF(" ... but not getting it because we are not a certificate.");

					break;
				}

				if (certificate_len >= 0) {
					x509_read_ret = x509_to_subject(certificate, certificate_len, &pValue);
					if (x509_read_ret < 0) {
						pValue = NULL;
					} else {
						ulValueLen = x509_read_ret;
					}
				}

				CACKEY_DEBUG_PRINTF(" ... returning %p/%lu", pValue, (unsigned long) ulValueLen);

				break;
			case CKA_ID:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_ID (0x%08lx) ...", (unsigned long) curr_attr_type);

				ucTmpBuf[0] = ((identity_num + 1) >> 8) & 0xff;
				ucTmpBuf[1] =  (identity_num + 1) & 0xff;

				pValue = &ucTmpBuf;
				ulValueLen = 2;

				CACKEY_DEBUG_PRINTF(" ... returning %p/%lu", pValue, (unsigned long) ulValueLen);

				break;
			case CKA_CERTIFICATE_TYPE:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_CERTIFICATE_TYPE (0x%08lx) ...", (unsigned long) curr_attr_type);

				if (objectclass != CKO_CERTIFICATE) {
					CACKEY_DEBUG_PRINTF(" ... but not getting it because we are not a certificate.");

					break;
				}

				/* We only support one certificate type */
				ck_certificate_type = CKC_X_509;

				pValue = &ck_certificate_type;
				ulValueLen = sizeof(ck_certificate_type);

				CACKEY_DEBUG_PRINTF(" ... returning CKC_X_509 (%lu) (%p/%lu)", (unsigned long) *((CK_CERTIFICATE_TYPE *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_KEY_TYPE:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_KEY_TYPE (0x%08lx) ...", (unsigned long) curr_attr_type);

				if (objectclass != CKO_PRIVATE_KEY && objectclass != CKO_PUBLIC_KEY) {
					CACKEY_DEBUG_PRINTF(" ... but not getting it because we are not a key.");

					break;
				}

				/* We only support one key type */
				ck_key_type = CKK_RSA;

				pValue = &ck_key_type;
				ulValueLen = sizeof(ck_key_type);

				CACKEY_DEBUG_PRINTF(" ... returning CKK_RSA (%lu) (%p/%lu)", (unsigned long) *((CK_CERTIFICATE_TYPE *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_SIGN:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_SIGN (0x%08lx) ...", (unsigned long) curr_attr_type);

				if (objectclass == CKO_PRIVATE_KEY) {
					pValue = &ck_true;
					ulValueLen = sizeof(ck_true);
				} else {
					pValue = &ck_false;
					ulValueLen = sizeof(ck_false);
				}

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_BBOOL *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_DECRYPT:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_DECRYPT (0x%08lx) ...", (unsigned long) curr_attr_type);

				if (objectclass == CKO_PRIVATE_KEY || objectclass == CKO_PUBLIC_KEY) {
					pValue = &ck_true;
					ulValueLen = sizeof(ck_true);
				} else {
					pValue = &ck_false;
					ulValueLen = sizeof(ck_false);
				}

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_BBOOL *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_TRUST_SERVER_AUTH:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_TRUST_SERVER_AUTH (0x%08lx) ...", (unsigned long) curr_attr_type);

				pValue = &ck_true;
				ulValueLen = sizeof(ck_true);

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_BBOOL *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_TRUST_CLIENT_AUTH:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_TRUST_CLIENT_AUTH (0x%08lx) ...", (unsigned long) curr_attr_type);

				pValue = &ck_true;
				ulValueLen = sizeof(ck_true);

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_BBOOL *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_TRUST_CODE_SIGNING:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_TRUST_CODE_SIGNING (0x%08lx) ...", (unsigned long) curr_attr_type);

				pValue = &ck_true;
				ulValueLen = sizeof(ck_true);

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_BBOOL *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			case CKA_TRUST_EMAIL_PROTECTION:
				CACKEY_DEBUG_PRINTF("Requesting attribute CKA_TRUST_EMAIL_PROTECTION (0x%08lx) ...", (unsigned long) curr_attr_type);

				pValue = &ck_true;
				ulValueLen = sizeof(ck_true);

				CACKEY_DEBUG_PRINTF(" ... returning %lu (%p/%lu)", (unsigned long) *((CK_BBOOL *) pValue), pValue, (unsigned long) ulValueLen);

				break;
			default:
				pValue = NULL;
				ulValueLen = (CK_LONG) -1;
				break;
		}

		if (((CK_LONG) ulValueLen) != ((CK_LONG) -1)) {
			/* Push curr_attr onto the stack */
			curr_attr.type = curr_attr_type;
			curr_attr.ulValueLen = ulValueLen;

			curr_attr.pValue = malloc(curr_attr.ulValueLen);
			memcpy(curr_attr.pValue, pValue, curr_attr.ulValueLen);

			if (pValue_free && pValue) {
				free(pValue);
			}

			if (numattrs >= retval_count) {
				retval_count *= 2;
				retval = realloc(retval, retval_count * sizeof(*retval));
			}

			memcpy(&retval[numattrs], &curr_attr, sizeof(curr_attr));
			numattrs++;
		}
	}

	if (numattrs != 0) {
		retval_count = numattrs;
		retval = realloc(retval, retval_count * sizeof(*retval));
	} else {
		free(retval);

		retval = NULL;
	}

	*pulCount = numattrs;

	CACKEY_DEBUG_PRINTF("Returning %lu objects (%p).", numattrs, retval);

	return(retval);
}

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs) {
	CK_C_INITIALIZE_ARGS CK_PTR args;
	uint32_t idx;
	int mutex_init_ret;

	CACKEY_DEBUG_PRINTF("Called.");

	if (pInitArgs != NULL) {
		args = pInitArgs;
		memcpy(&cackey_args, args, sizeof(cackey_args));

		if (args->CreateMutex == NULL || args->DestroyMutex == NULL || args->LockMutex == NULL || args->UnlockMutex == NULL) {
			if (args->CreateMutex != NULL || args->DestroyMutex != NULL || args->LockMutex != NULL || args->UnlockMutex != NULL) {
				CACKEY_DEBUG_PRINTF("Error. Some, but not All threading primitives provided.");

				return(CKR_ARGUMENTS_BAD);
			}
		}

		if (args->pReserved != NULL) {
			CACKEY_DEBUG_PRINTF("Error. pReserved is not NULL.");

			return(CKR_ARGUMENTS_BAD);
		}
	} else {
		cackey_args.CreateMutex = NULL;
		cackey_args.DestroyMutex = NULL;
		cackey_args.LockMutex = NULL;
		cackey_args.UnlockMutex = NULL;
		cackey_args.flags = 0;
	}

	if (cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Already initialized.");

		return(CKR_CRYPTOKI_ALREADY_INITIALIZED);
	}

	for (idx = 0; idx < (sizeof(cackey_sessions) / sizeof(cackey_sessions[0])); idx++) {
		cackey_sessions[idx].active = 0;
	}

	cackey_initialized = 1;

	if (!cackey_biglock_init) {
		mutex_init_ret = cackey_mutex_create(&cackey_biglock);

		if (mutex_init_ret != 0) {
			CACKEY_DEBUG_PRINTF("Error.  Mutex initialization failed.");

			return(CKR_CANT_LOCK);
		}

		cackey_biglock_init = 1;
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved) {
	uint32_t idx;

	CACKEY_DEBUG_PRINTF("Called.");

	if (pReserved != NULL) {
		CACKEY_DEBUG_PRINTF("Error. pReserved is not NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	for (idx = 0; idx < (sizeof(cackey_sessions) / sizeof(cackey_sessions[0])); idx++) {
		if (cackey_sessions[idx].active) {
			C_CloseSession(idx);
		}
	}

	cackey_initialized = 0;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo) {
	static CK_UTF8CHAR manufacturerID[] = "U.S. Government";
	static CK_UTF8CHAR libraryDescription[] = "SSH Agent PKCS#11";

	CACKEY_DEBUG_PRINTF("Called.");

	if (pInfo == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pInfo is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	pInfo->cryptokiVersion.major = ((CACKEY_CRYPTOKI_VERSION_CODE) >> 16) & 0xff;
	pInfo->cryptokiVersion.minor = ((CACKEY_CRYPTOKI_VERSION_CODE) >> 8) & 0xff;

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, manufacturerID, sizeof(manufacturerID) - 1);

	pInfo->flags = 0x00;

	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, libraryDescription, sizeof(libraryDescription) - 1);

	pInfo->libraryVersion.major = (cackey_getversion() >> 16) & 0xff;
	pInfo->libraryVersion.minor = (cackey_getversion() >> 8) & 0xff;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

/* We only support 1 slot.  If the slot exists, the token exists. */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	CK_ULONG count, slot_present = 0, currslot;
	int fd;

	CACKEY_DEBUG_PRINTF("Called.");

	if (pulCount == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pulCount is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* XXX: Determine if slot is present */

	if (pSlotList == NULL) {
		*pulCount = slot_present;

		CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

		return(CKR_OK);
	}

	count = *pulCount;
	if (count < slot_present) {
		CACKEY_DEBUG_PRINTF("Error. User allocated %lu entries, but we have %lu entries.", count, slot_present);

		return(CKR_BUFFER_TOO_SMALL);	
	}

	for (currslot = 0; currslot < slot_present; currslot++) {
		pSlotList[currslot] = currslot;
	}

	*pulCount = slot_present;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);

	tokenPresent = tokenPresent; /* Supress unused variable warning */
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
	static CK_UTF8CHAR manufacturerID[] = "U.S. Government";
	static CK_UTF8CHAR slotDescription[] = "SSH Agent Slot";

	CACKEY_DEBUG_PRINTF("Called.");

	if (pInfo == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pInfo is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (slotID != 0) {
		/* Again, we only support one slot -- slot 0 */
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), only one slot available: 0", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, slotDescription, sizeof(slotDescription) - 1);

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, manufacturerID, sizeof(manufacturerID) - 1);

	pInfo->flags = CKF_TOKEN_PRESENT;

	pInfo->hardwareVersion.major = (cackey_getversion() >> 16) & 0xff;
	pInfo->hardwareVersion.minor = (cackey_getversion() >> 8) & 0xff;

	pInfo->firmwareVersion.major = 0x00;
	pInfo->firmwareVersion.minor = 0x00;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
	static CK_UTF8CHAR manufacturerID[] = "U.S. Government";
	static CK_UTF8CHAR defaultLabel[] = "Unknown Token";
	static CK_UTF8CHAR model[] = "SSH Agent Token";
	int fd, bytestocopy;

	CACKEY_DEBUG_PRINTF("Called.");

	if (pInfo == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pInfo is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (slotID != 0) {
		/* Again, we only support one slot -- slot 0 */
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), only one slot available: 0", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* XXX: Verify connection is valid */
	if (0) {
		CACKEY_DEBUG_PRINTF("Error. Tried to connect to slot, but failed.  fd = %i", fd);

		return(CKR_SLOT_ID_INVALID);
	}

	/* XXX: Get list of identities */
	if (0) {
		CACKEY_DEBUG_PRINTF("Error. No identities found in slot.");

		return(CKR_TOKEN_NOT_PRESENT);
	}

	memset(pInfo->label, ' ', sizeof(pInfo->label));
	if (1) {
		memcpy(pInfo->label, defaultLabel, sizeof(defaultLabel) - 1);
	} else {
	}

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, manufacturerID, sizeof(manufacturerID) - 1);

	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memcpy(pInfo->model, model, sizeof(model) - 1);

	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));

	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

	pInfo->hardwareVersion.major = (cackey_getversion() >> 16) & 0xff;
	pInfo->hardwareVersion.minor = (cackey_getversion() >> 8) & 0xff;

	pInfo->firmwareVersion.major = 0x00;
	pInfo->firmwareVersion.minor = 0x00;

	pInfo->flags = CKF_WRITE_PROTECTED | CKF_USER_PIN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_TOKEN_INITIALIZED;

	pInfo->ulMaxSessionCount = (sizeof(cackey_sessions) / sizeof(cackey_sessions[0])) - 1;
	pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulMaxRwSessionCount = 0;
	pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulMaxPinLen = 128;
	pInfo->ulMinPinLen = 0;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlotID, CK_VOID_PTR pReserved) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (pReserved != NULL) {
		CACKEY_DEBUG_PRINTF("Error. pReserved is not NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pulCount == NULL) {
		CACKEY_DEBUG_PRINTF("Error.  pulCount is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (pMechanismList == NULL) {
		*pulCount = 3;

		CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

		return(CKR_OK);
	}

	if (*pulCount < 3) {
		CACKEY_DEBUG_PRINTF("Error.  Buffer too small.");

		return(CKR_BUFFER_TOO_SMALL);
	}

	pMechanismList[0] = CKM_RSA_PKCS;
	pMechanismList[1] = CKM_SHA1_RSA_PKCS;
	*pulCount = 2;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (slotID != 0) {
		/* Again, we only support one slot -- slot 0 */
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), only one slot available: 0", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (pInfo == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pInfo is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* XXX: This is untested, and further I'm not really sure if this is correct. */
	switch (type) {
		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 8192;
			pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_X_509:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 8192;
			pInfo->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA1_RSA_PKCS:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 8192;
			pInfo->flags = CKF_HW | CKF_SIGN | CKF_VERIFY;
			break;
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

/* We don't support this method. */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_TOKEN_WRITE_PROTECTED (%i)", CKR_TOKEN_WRITE_PROTECTED);

	return(CKR_TOKEN_WRITE_PROTECTED);
}

/* We don't support this method. */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_TOKEN_WRITE_PROTECTED (%i)", CKR_TOKEN_WRITE_PROTECTED);

	return(CKR_TOKEN_WRITE_PROTECTED);
}

/* We don't support this method. */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession) {
	struct cackey_identity *identities;
	unsigned long idx, num_ids, id_idx, curr_id_type, curr_ssh_id_idx;
	CK_BYTE sigbuf[1024];
	ssize_t sigbuflen;
	int mutex_retval;
	int found_session = 0;
	int fd;

	CACKEY_DEBUG_PRINTF("Called.");

	if (slotID != 0) {
		/* We only support one slot -- slot 0 */
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), only one slot available: 0", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if ((flags & CKF_SERIAL_SESSION) != CKF_SERIAL_SESSION) {
		return(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Verify that the card is actually in the slot. */
	/* XXX: Talk to card */
	if (0) {
		if (0) {
			CACKEY_DEBUG_PRINTF("Error.  Card not present.  Returning CKR_DEVICE_REMOVED");

			return(CKR_DEVICE_REMOVED);
		}
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	for (idx = 1; idx < (sizeof(cackey_sessions) / sizeof(cackey_sessions[0])); idx++) {
		if (!cackey_sessions[idx].active) {
			found_session = 1;

			*phSession = idx;

			cackey_sessions[idx].active = 1;
			cackey_sessions[idx].slotID = slotID;
			cackey_sessions[idx].state = CKS_RO_PUBLIC_SESSION;
			cackey_sessions[idx].flags = flags;
			cackey_sessions[idx].ulDeviceError = 0;
			cackey_sessions[idx].pApplication = pApplication;
			cackey_sessions[idx].Notify = notify;

			cackey_sessions[idx].identities = NULL;
			cackey_sessions[idx].identities_count = 0;

			if (0) {
				num_ids = 0;
				/* XXX: Determine number of IDs */

				/* Convert number of IDs to number of objects */
				num_ids = (CKO_PRIVATE_KEY - CKO_CERTIFICATE + 1) * num_ids;

				identities = malloc(num_ids * sizeof(*identities));

				id_idx = 0;
				for (;;) {
					for (curr_id_type = CKO_CERTIFICATE; curr_id_type <= CKO_PRIVATE_KEY; curr_id_type++) {
						/* XXX: Determine base index */

						identities[id_idx].attributes = cackey_get_attributes(curr_id_type, NULL, -1, &identities[id_idx].attributes_count);

						if (identities[id_idx].attributes == NULL) {
							identities[id_idx].attributes_count = 0;
						}

						id_idx++;
					}
				}

				cackey_sessions[idx].identities = identities;
				cackey_sessions[idx].identities_count = num_ids;
			}

			cackey_sessions[idx].search_active = 0;

			cackey_sessions[idx].sign_active = 0;

			cackey_sessions[idx].decrypt_active = 0;

			break;
		}
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!found_session) {
		CACKEY_DEBUG_PRINTF("Returning CKR_SESSION_COUNT (%i)", CKR_SESSION_COUNT);

		return(CKR_SESSION_COUNT);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession) {
	CK_ATTRIBUTE *curr_attr;
	unsigned long id_idx, attr_idx;
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	cackey_sessions[hSession].active = 0;
	if (cackey_sessions[hSession].identities) {
		for (id_idx = 0; id_idx < cackey_sessions[hSession].identities_count; id_idx++) {
			if (cackey_sessions[hSession].identities[id_idx].attributes) {
				for (attr_idx = 0; attr_idx < cackey_sessions[hSession].identities[id_idx].attributes_count; attr_idx++) {
					curr_attr = &cackey_sessions[hSession].identities[id_idx].attributes[attr_idx];

					if (curr_attr->pValue) {
						free(curr_attr->pValue);
					}
				}

				free(cackey_sessions[hSession].identities[id_idx].attributes);
			}
		}

		free(cackey_sessions[hSession].identities);
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID) {
	uint32_t idx;
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (slotID != 0) {
		/* Again, we only support one slot -- slot 0 */
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), only one slot available: 0", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	for (idx = 0; idx < (sizeof(cackey_sessions) / sizeof(cackey_sessions[0])); idx++) {
		if (cackey_sessions[idx].active) {
			if (cackey_sessions[idx].slotID != slotID) {
				continue;
			}

			cackey_mutex_unlock(cackey_biglock);
			C_CloseSession(idx);
			cackey_mutex_lock(cackey_biglock);
		}
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (pInfo == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pInfo is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	pInfo->slotID = cackey_sessions[hSession].slotID;
	pInfo->state = cackey_sessions[hSession].state;
	pInfo->flags = cackey_sessions[hSession].flags;
	pInfo->ulDeviceError = cackey_sessions[hSession].ulDeviceError;

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (userType != CKU_USER) {
		CACKEY_DEBUG_PRINTF("Error.  We only support USER mode, asked for %lu mode.", (unsigned long) userType)

		return(CKR_USER_TYPE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	cackey_sessions[hSession].state = CKS_RO_USER_FUNCTIONS;

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession) {
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	cackey_sessions[hSession].state = CKS_RO_PUBLIC_SESSION;

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	CK_ATTRIBUTE *curr_attr;
	struct cackey_identity *identity;
	unsigned long identity_idx, attr_idx, sess_attr_idx, num_ids;
	int mutex_retval;
	CK_RV retval = CKR_OK;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (hObject == 0) {
		CACKEY_DEBUG_PRINTF("Error.  Object handle out of range.");
		
		return(CKR_OBJECT_HANDLE_INVALID);
	}

	if (ulCount == 0) {
		/* Short circuit, if zero objects were specified return zero items immediately */
		CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i) (short circuit)", CKR_OK);

		return(CKR_OK);
	}

	if (pTemplate == NULL) {
		CACKEY_DEBUG_PRINTF("Error.  pTemplate is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	identity_idx = hObject - 1;

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	num_ids = cackey_sessions[hSession].identities_count;

	if (identity_idx >= num_ids) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Object handle out of range.  identity_idx = %lu, num_ids = %lu.", (unsigned long) identity_idx, (unsigned long) num_ids);

		return(CKR_OBJECT_HANDLE_INVALID);
	}

	identity = &cackey_sessions[hSession].identities[identity_idx];

	for (attr_idx = 0; attr_idx < ulCount; attr_idx++) {
		curr_attr = &pTemplate[attr_idx];

		pValue = NULL;
		ulValueLen = (CK_LONG) -1;

		CACKEY_DEBUG_PRINTF("Looking for attribute 0x%08lx (identity:%lu) ...", (unsigned long) curr_attr->type, (unsigned long) identity_idx);

		for (sess_attr_idx = 0; sess_attr_idx < identity->attributes_count; sess_attr_idx++) {
			if (identity->attributes[sess_attr_idx].type == curr_attr->type) {
				CACKEY_DEBUG_PRINTF(" ... found it, pValue = %p, ulValueLen = %lu", identity->attributes[sess_attr_idx].pValue, identity->attributes[sess_attr_idx].ulValueLen);
				
				pValue = identity->attributes[sess_attr_idx].pValue;
				ulValueLen = identity->attributes[sess_attr_idx].ulValueLen;
			}
		}

		if (curr_attr->pValue && pValue) {
			if (curr_attr->ulValueLen >= ulValueLen) {
				memcpy(curr_attr->pValue, pValue, ulValueLen);
			} else {
				ulValueLen = (CK_LONG) -1;

				retval = CKR_BUFFER_TOO_SMALL;
			}
		}

		curr_attr->ulValueLen = ulValueLen;
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (retval == CKR_ATTRIBUTE_TYPE_INVALID) {
		CACKEY_DEBUG_PRINTF("Returning CKR_ATTRIBUTE_TYPE_INVALID (%i)", (int) retval);
	} else if (retval == CKR_BUFFER_TOO_SMALL) {
		CACKEY_DEBUG_PRINTF("Returning CKR_BUFFER_TOO_SMALL (%i)", (int) retval);
	} else if (retval == CKR_OK) {
		CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", (int) retval);
	} else {
		CACKEY_DEBUG_PRINTF("Returning %i", (int) retval);
	}

	return(retval);
}

CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (cackey_sessions[hSession].search_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Search already active.");
		
		return(CKR_OPERATION_ACTIVE);
	}

	if (pTemplate != NULL) {
		if (ulCount != 0) {
			cackey_sessions[hSession].search_query_count = ulCount;
			cackey_sessions[hSession].search_query = malloc(ulCount * sizeof(*pTemplate));

			memcpy(cackey_sessions[hSession].search_query, pTemplate, ulCount * sizeof(*pTemplate));
		} else {
			cackey_sessions[hSession].search_query_count = 0;
			cackey_sessions[hSession].search_query = NULL;
		}
	} else {
		if (ulCount != 0) {
			cackey_mutex_unlock(cackey_biglock);

			CACKEY_DEBUG_PRINTF("Error.  Search query specified as NULL, but number of query terms not specified as 0.");

			return(CKR_ARGUMENTS_BAD);
		}

		cackey_sessions[hSession].search_query_count = 0;
		cackey_sessions[hSession].search_query = NULL;
	}

	cackey_sessions[hSession].search_active = 1;
	cackey_sessions[hSession].search_curr_id = 0;

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
	struct cackey_identity *curr_id;
	CK_ATTRIBUTE *curr_attr;
	CK_ULONG curr_id_idx, curr_out_id_idx, curr_attr_idx, sess_attr_idx;
	CK_ULONG matched_count, prev_matched_count;
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pulObjectCount == NULL) {
		CACKEY_DEBUG_PRINTF("Error.  pulObjectCount is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (phObject == NULL && ulMaxObjectCount == 0) {
		/* Short circuit, if zero objects were specified return zero items immediately */
		*pulObjectCount = 0;

		CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i) (short circuit)", CKR_OK);

		return(CKR_OK);
	}

	if (phObject == NULL) {
		CACKEY_DEBUG_PRINTF("Error.  phObject is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (ulMaxObjectCount == 0) {
		CACKEY_DEBUG_PRINTF("Error.  Maximum number of objects specified as zero.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (!cackey_sessions[hSession].search_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Search not active.");
		
		return(CKR_OPERATION_NOT_INITIALIZED);
	}

	curr_id_idx = 0;
	curr_out_id_idx = 0;
	for (curr_id_idx = cackey_sessions[hSession].search_curr_id; curr_id_idx < cackey_sessions[hSession].identities_count && ulMaxObjectCount; curr_id_idx++) {
		curr_id = &cackey_sessions[hSession].identities[curr_id_idx];

		CACKEY_DEBUG_PRINTF("Processing identity:%lu", (unsigned long) curr_id_idx);

		matched_count = 0;

		for (curr_attr_idx = 0; curr_attr_idx < cackey_sessions[hSession].search_query_count; curr_attr_idx++) {
			prev_matched_count = matched_count;

			curr_attr = &cackey_sessions[hSession].search_query[curr_attr_idx];

			CACKEY_DEBUG_PRINTF("  Checking for attribute 0x%08lx in identity:%i...", (unsigned long) curr_attr->type, (int) curr_id_idx);
			CACKEY_DEBUG_PRINTBUF("    Value looking for:", curr_attr->pValue, curr_attr->ulValueLen);

			for (sess_attr_idx = 0; sess_attr_idx < curr_id->attributes_count; sess_attr_idx++) {
				if (curr_id->attributes[sess_attr_idx].type == curr_attr->type) {
					CACKEY_DEBUG_PRINTF("    ... found matching type ...");
					CACKEY_DEBUG_PRINTBUF("    ... our value:", curr_id->attributes[sess_attr_idx].pValue, curr_id->attributes[sess_attr_idx].ulValueLen);

					if (curr_attr->pValue == NULL) {
						CACKEY_DEBUG_PRINTF("       ... found wildcard match");

						matched_count++;

						break;
					}

 					if (curr_attr->ulValueLen == curr_id->attributes[sess_attr_idx].ulValueLen && memcmp(curr_attr->pValue, curr_id->attributes[sess_attr_idx].pValue, curr_id->attributes[sess_attr_idx].ulValueLen) == 0) {
						CACKEY_DEBUG_PRINTF("       ... found exact match");

						matched_count++;

						break;
					}
				}
			}

			/* If the attribute could not be matched, do not try to match additional attributes */
			if (prev_matched_count == matched_count) {
				break;
			}
		}

		if (matched_count == cackey_sessions[hSession].search_query_count) {
			CACKEY_DEBUG_PRINTF("  ... All %i attributes checked for found, adding identity:%i to returned list", (int) cackey_sessions[hSession].search_query_count, (int) curr_id_idx);

			phObject[curr_out_id_idx] = curr_id_idx + 1;

			ulMaxObjectCount--;

			curr_out_id_idx++;
		} else {
			CACKEY_DEBUG_PRINTF("  ... Not all %i (only found %i) attributes checked for found, not adding identity:%i", (int) cackey_sessions[hSession].search_query_count, (int) matched_count, (int) curr_id_idx);
		}
	}
	cackey_sessions[hSession].search_curr_id = curr_id_idx;
	*pulObjectCount = curr_out_id_idx;

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i), num objects = %lu", CKR_OK, *pulObjectCount);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession) {
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (!cackey_sessions[hSession].search_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Search not active.");
		
		return(CKR_OPERATION_NOT_INITIALIZED);
	}

	cackey_sessions[hSession].search_active = 0;
	if (cackey_sessions[hSession].search_query) {
		free(cackey_sessions[hSession].search_query);
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	int mutex_retval;

	hKey--;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pMechanism == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pMechanism is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (pMechanism->mechanism != CKM_RSA_PKCS) {
		CACKEY_DEBUG_PRINTF("Error. pMechanism->mechanism not specified as CKM_RSA_PKCS");

		return(CKR_MECHANISM_PARAM_INVALID);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (cackey_sessions[hSession].decrypt_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Decrypt already in progress.");
		
		return(CKR_OPERATION_ACTIVE);
	}

	if (hKey >= cackey_sessions[hSession].identities_count) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Key handle out of range.");

		return(CKR_KEY_HANDLE_INVALID);
	}

	cackey_sessions[hSession].decrypt_active = 1;

	cackey_sessions[hSession].decrypt_mechanism = pMechanism->mechanism;
	cackey_sessions[hSession].decrypt_mech_parm = pMechanism->pParameter;
	cackey_sessions[hSession].decrypt_mech_parmlen = pMechanism->ulParameterLen;

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
	CK_ULONG datalen_update, datalen_final;
	CK_RV decrypt_ret;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pulDataLen == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pulDataLen is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	datalen_update = *pulDataLen;

	decrypt_ret = C_DecryptUpdate(hSession, pEncryptedData, ulEncryptedDataLen, pData, &datalen_update);
	if (decrypt_ret != CKR_OK) {
		CACKEY_DEBUG_PRINTF("Error.  DecryptUpdate() returned failure (rv = %lu).", (unsigned long) decrypt_ret);

		return(decrypt_ret);
	}

	if (pData) {
		pData += datalen_update;
	}
	datalen_final = *pulDataLen - datalen_update;

	decrypt_ret = C_DecryptFinal(hSession, pData, &datalen_final);
	if (decrypt_ret != CKR_OK) {
		CACKEY_DEBUG_PRINTF("Error.  DecryptFinal() returned failure (rv = %lu).", (unsigned long) decrypt_ret);

		return(decrypt_ret);
	}

	*pulDataLen = datalen_update + datalen_final;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
	static CK_BYTE buf[16384];
	ssize_t buflen;
	CK_RV retval = CKR_GENERAL_ERROR;
	int mutex_retval;
	int fd;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (pEncryptedPart == NULL && ulEncryptedPartLen == 0) {
		/* Short circuit if we are asked to decrypt nothing... */
		CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i) (short circuit)", CKR_OK);

		return(CKR_OK);
	}

	if (pEncryptedPart == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pEncryptedPart is NULL, but ulEncryptedPartLen is not 0.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (ulEncryptedPartLen == 0) {
		CACKEY_DEBUG_PRINTF("Error. ulEncryptedPartLen is 0, but pPart is not NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (pulPartLen == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pulPartLen is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (!cackey_sessions[hSession].decrypt_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Decrypt not active.");
		
		return(CKR_OPERATION_NOT_INITIALIZED);
	}

	switch (cackey_sessions[hSession].decrypt_mechanism) {
		case CKM_RSA_PKCS:
			buflen = -1;

			/* XXX: Ask card to decrypt */

			if (buflen < 0) {
				/* Decryption failed. */
				retval = CKR_GENERAL_ERROR;
			} else if (((unsigned long) buflen) > *pulPartLen && pPart) {
				/* Decrypted data too large */
				retval = CKR_BUFFER_TOO_SMALL;
			} else {
				if (pPart) {
					memcpy(pPart, buf, buflen);
				}

				*pulPartLen = buflen;

				retval = CKR_OK;
			}

			break;
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning %i", (int) retval);

	return(retval);
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
	int mutex_retval;
	int terminate_decrypt = 1;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (pulLastPartLen == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pulLastPartLen is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (!cackey_sessions[hSession].decrypt_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Decrypt not active.");
		
		return(CKR_OPERATION_NOT_INITIALIZED);
	}

	*pulLastPartLen = 0;

	if (pLastPart == NULL) {
		terminate_decrypt = 0;
	}

	if (terminate_decrypt) {
		cackey_sessions[hSession].decrypt_active = 0;
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	int mutex_retval;

	hKey--;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pMechanism == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pMechanism is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (pMechanism->mechanism != CKM_RSA_PKCS && pMechanism->mechanism != CKM_SHA1_RSA_PKCS) {
		CACKEY_DEBUG_PRINTF("Error. pMechanism->mechanism not specified as CKM_RSA_PKCS or CKM_SHA1_RSA_PKCS");

		return(CKR_MECHANISM_PARAM_INVALID);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (cackey_sessions[hSession].sign_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Sign already in progress.");
		
		return(CKR_OPERATION_ACTIVE);
	}

	if (hKey >= cackey_sessions[hSession].identities_count) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Key handle out of range.");

		return(CKR_KEY_HANDLE_INVALID);
	}

	cackey_sessions[hSession].sign_active = 1;

	cackey_sessions[hSession].sign_mechanism = pMechanism->mechanism;

	cackey_sessions[hSession].sign_buflen = 128;
	cackey_sessions[hSession].sign_bufused = 0;
	cackey_sessions[hSession].sign_buf = malloc(sizeof(*cackey_sessions[hSession].sign_buf) * cackey_sessions[hSession].sign_buflen);

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	CK_RV sign_ret;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	sign_ret = C_SignUpdate(hSession, pData, ulDataLen);
	if (sign_ret != CKR_OK) {
		CACKEY_DEBUG_PRINTF("Error.  SignUpdate() returned failure (rv = %lu).", (unsigned long) sign_ret);

		return(sign_ret);
	}

	sign_ret = C_SignFinal(hSession, pSignature, pulSignatureLen);
	if (sign_ret != CKR_OK) {
		CACKEY_DEBUG_PRINTF("Error.  SignFinal() returned failure (rv = %lu).", (unsigned long) sign_ret);

		return(sign_ret);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
	int mutex_retval;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (pPart == NULL && ulPartLen == 0) {
		/* Short circuit if we are asked to sign nothing... */
		CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i) (short circuit)", CKR_OK);

		return(CKR_OK);
	}

	if (pPart == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pPart is NULL, but ulPartLen is not 0.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (ulPartLen == 0) {
		CACKEY_DEBUG_PRINTF("Error. ulPartLen is 0, but pPart is not NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (!cackey_sessions[hSession].sign_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Sign not active.");
		
		return(CKR_OPERATION_NOT_INITIALIZED);
	}

	switch (cackey_sessions[hSession].sign_mechanism) {
		case CKM_RSA_PKCS:
			/* Accumulate directly */
			if ((cackey_sessions[hSession].sign_bufused + ulPartLen) > cackey_sessions[hSession].sign_buflen) {
				cackey_sessions[hSession].sign_buflen *= 2;

				cackey_sessions[hSession].sign_buf = realloc(cackey_sessions[hSession].sign_buf, sizeof(*cackey_sessions[hSession].sign_buf) * cackey_sessions[hSession].sign_buflen);
			}

			memcpy(cackey_sessions[hSession].sign_buf + cackey_sessions[hSession].sign_bufused, pPart, ulPartLen);

			cackey_sessions[hSession].sign_bufused += ulPartLen;

			break;
		case CKM_SHA1_RSA_PKCS:
			/* Accumulate into a SHA1 hash */
			cackey_mutex_unlock(cackey_biglock);

			CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

			return(CKR_FUNCTION_NOT_SUPPORTED);
			break;
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	static CK_BYTE sigbuf[1024];
	ssize_t sigbuflen;
	CK_RV retval = CKR_GENERAL_ERROR;
	int terminate_sign = 1;
	int mutex_retval;
	int fd;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pulSignatureLen == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pulSignatureLen is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (hSession == 0 || hSession >= (sizeof(cackey_sessions) / sizeof(cackey_sessions[0]))) {
		CACKEY_DEBUG_PRINTF("Error.  Session out of range.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	mutex_retval = cackey_mutex_lock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Locking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (!cackey_sessions[hSession].active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Session not active.");
		
		return(CKR_SESSION_HANDLE_INVALID);
	}

	if (!cackey_sessions[hSession].sign_active) {
		cackey_mutex_unlock(cackey_biglock);

		CACKEY_DEBUG_PRINTF("Error.  Sign not active.");
		
		return(CKR_OPERATION_NOT_INITIALIZED);
	}

	switch (cackey_sessions[hSession].sign_mechanism) {
		case CKM_RSA_PKCS:
			sigbuflen = -1;

			/* XXX: Ask card to sign */

			if (sigbuflen < 0) {
				/* Signing failed. */
				retval = CKR_GENERAL_ERROR;
			} else if (((unsigned long) sigbuflen) > *pulSignatureLen && pSignature) {
				/* Signed data too large */
				retval = CKR_BUFFER_TOO_SMALL;

				terminate_sign = 0;
			} else {
				terminate_sign = 0;

				if (pSignature) {
					memcpy(pSignature, sigbuf, sigbuflen);

					terminate_sign = 1;
				}

				*pulSignatureLen = sigbuflen;

				retval = CKR_OK;
			}

			break;
		case CKM_SHA1_RSA_PKCS:
			/* Accumulate into a SHA1 hash */
			cackey_mutex_unlock(cackey_biglock);

			CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

			return(CKR_FUNCTION_NOT_SUPPORTED);
			break;
	}

	if (terminate_sign) {
		if (cackey_sessions[hSession].sign_buf) {
			free(cackey_sessions[hSession].sign_buf);
		}

		cackey_sessions[hSession].sign_active = 0;
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	CACKEY_DEBUG_PRINTF("Returning %i", (int) retval);

	return(retval);
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
	CACKEY_DEBUG_PRINTF("Called.");

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_SUPPORTED (%i)", CKR_FUNCTION_NOT_SUPPORTED);

	return(CKR_FUNCTION_NOT_SUPPORTED);
}

/* Deprecated Function */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession) {
	CACKEY_DEBUG_PRINTF("Called.");

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_PARALLEL (%i)", CKR_FUNCTION_NOT_PARALLEL);

	return(CKR_FUNCTION_NOT_PARALLEL);

	hSession = hSession; /* Supress unused variable warning */
}

/* Deprecated Function */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession) {
	CACKEY_DEBUG_PRINTF("Called.");

	CACKEY_DEBUG_PRINTF("Returning CKR_FUNCTION_NOT_PARALLEL (%i)", CKR_FUNCTION_NOT_PARALLEL);

	return(CKR_FUNCTION_NOT_PARALLEL);

	hSession = hSession; /* Supress unused variable warning */
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	CK_FUNCTION_LIST_PTR pFunctionList;

	CACKEY_DEBUG_PRINTF("Called.");

	if (ppFunctionList == NULL) {
		CACKEY_DEBUG_PRINTF("Error. ppFunctionList is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	pFunctionList = malloc(sizeof(*pFunctionList));

	pFunctionList->version.major = ((CACKEY_CRYPTOKI_VERSION_CODE) >> 16) & 0xff;
	pFunctionList->version.minor = ((CACKEY_CRYPTOKI_VERSION_CODE) >> 8) & 0xff;

	pFunctionList->C_Initialize = C_Initialize;
	pFunctionList->C_Finalize = C_Finalize;
	pFunctionList->C_GetInfo = C_GetInfo;
	pFunctionList->C_GetSlotList = C_GetSlotList;
	pFunctionList->C_GetSlotInfo = C_GetSlotInfo;
	pFunctionList->C_GetTokenInfo = C_GetTokenInfo;
	pFunctionList->C_WaitForSlotEvent = C_WaitForSlotEvent;
	pFunctionList->C_GetMechanismList = C_GetMechanismList;
	pFunctionList->C_GetMechanismInfo = C_GetMechanismInfo;
	pFunctionList->C_InitToken = C_InitToken;
	pFunctionList->C_InitPIN = C_InitPIN;
	pFunctionList->C_SetPIN = C_SetPIN;
	pFunctionList->C_OpenSession = C_OpenSession;
	pFunctionList->C_CloseSession = C_CloseSession;
	pFunctionList->C_CloseAllSessions = C_CloseAllSessions;
	pFunctionList->C_GetSessionInfo = C_GetSessionInfo;
	pFunctionList->C_GetOperationState = C_GetOperationState;
	pFunctionList->C_SetOperationState = C_SetOperationState;
	pFunctionList->C_Login = C_Login;
	pFunctionList->C_Logout = C_Logout;
	pFunctionList->C_CreateObject = C_CreateObject;
	pFunctionList->C_CopyObject = C_CopyObject;
	pFunctionList->C_DestroyObject = C_DestroyObject;
	pFunctionList->C_GetObjectSize = C_GetObjectSize;
	pFunctionList->C_GetAttributeValue = C_GetAttributeValue;
	pFunctionList->C_SetAttributeValue = C_SetAttributeValue;
	pFunctionList->C_FindObjectsInit = C_FindObjectsInit;
	pFunctionList->C_FindObjects = C_FindObjects;
	pFunctionList->C_FindObjectsFinal = C_FindObjectsFinal;
	pFunctionList->C_EncryptInit = C_EncryptInit;
	pFunctionList->C_Encrypt = C_Encrypt;
	pFunctionList->C_EncryptUpdate = C_EncryptUpdate;
	pFunctionList->C_EncryptFinal = C_EncryptFinal;
	pFunctionList->C_DecryptInit = C_DecryptInit;
	pFunctionList->C_Decrypt = C_Decrypt;
	pFunctionList->C_DecryptUpdate = C_DecryptUpdate;
	pFunctionList->C_DecryptFinal = C_DecryptFinal;
	pFunctionList->C_DigestInit = C_DigestInit;
	pFunctionList->C_Digest = C_Digest;
	pFunctionList->C_DigestUpdate = C_DigestUpdate;
	pFunctionList->C_DigestKey = C_DigestKey;
	pFunctionList->C_DigestFinal = C_DigestFinal;
	pFunctionList->C_SignInit = C_SignInit;
	pFunctionList->C_Sign = C_Sign;
	pFunctionList->C_SignUpdate = C_SignUpdate;
	pFunctionList->C_SignFinal = C_SignFinal;
	pFunctionList->C_SignRecoverInit = C_SignRecoverInit;
	pFunctionList->C_SignRecover = C_SignRecover;
	pFunctionList->C_VerifyInit = C_VerifyInit;
	pFunctionList->C_Verify = C_Verify;
	pFunctionList->C_VerifyUpdate = C_VerifyUpdate;
	pFunctionList->C_VerifyFinal = C_VerifyFinal;
	pFunctionList->C_VerifyRecoverInit = C_VerifyRecoverInit;
	pFunctionList->C_VerifyRecover = C_VerifyRecover;
	pFunctionList->C_DigestEncryptUpdate = C_DigestEncryptUpdate;
	pFunctionList->C_DecryptDigestUpdate = C_DecryptDigestUpdate;
	pFunctionList->C_SignEncryptUpdate = C_SignEncryptUpdate;
	pFunctionList->C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
	pFunctionList->C_GenerateKey = C_GenerateKey;
	pFunctionList->C_GenerateKeyPair = C_GenerateKeyPair;
	pFunctionList->C_WrapKey = C_WrapKey;
	pFunctionList->C_UnwrapKey = C_UnwrapKey;
	pFunctionList->C_DeriveKey = C_DeriveKey;
	pFunctionList->C_SeedRandom = C_SeedRandom;
	pFunctionList->C_GenerateRandom = C_GenerateRandom;
	pFunctionList->C_GetFunctionStatus = C_GetFunctionStatus;
	pFunctionList->C_CancelFunction = C_CancelFunction;
	pFunctionList->C_GetFunctionList = C_GetFunctionList;

	*ppFunctionList = pFunctionList;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

