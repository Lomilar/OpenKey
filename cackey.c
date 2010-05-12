#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_PCSCLITE_H
#  include <pcsclite.h>
#endif
#ifdef HAVE_WINSCARD_H
#  include <winscard.h>
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
#include "asn1-x509.h"

#ifndef CACKEY_CRYPTOKI_VERSION_CODE
#  define CACKEY_CRYPTOKI_VERSION_CODE 0x021e00
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

/* GSC-IS v2.1 Definitions */
/** Classes **/
#define GSCIS_CLASS_ISO7816           0x00
#define GSCIS_CLASS_GLOBAL_PLATFORM   0x80

/** Instructions **/
#define GSCIS_INSTR_GET_RESPONSE      0xC0
#define GSCIS_INSTR_READ_BINARY       0xB0
#define GSCIS_INSTR_UPDATE_BINARY     0xD6
#define GSCIS_INSTR_SELECT            0xA4
#define GSCIS_INSTR_EXTERNAL_AUTH     0x82
#define GSCIS_INSTR_GET_CHALLENGE     0x84
#define GSCIS_INSTR_INTERNAL_AUTH     0x88
#define GSCIS_INSTR_VERIFY            0x20
#define GSCIS_INSTR_SIGN              0x2A
#define GSCIS_INSTR_GET_PROP          0x56
#define GSCIS_INSTR_GET_ACR           0x4C
#define GSCIS_INSTR_READ_BUFFER       0x52
#define GSCIS_INSTR_SIGNDECRYPT       0x42

#define GSCIS_PARAM_SELECT_APPLET     0x04

/** Tags **/
/*** CCC Tags ***/
#define GSCIS_TAG_CARDID              0xF0
#define GSCIS_TAG_CCC_VER             0xF1
#define GSCIS_TAG_CCG_VER             0xF2
#define GSCIS_TAG_CARDURL             0xF3
#define GSCIS_TAG_PKCS15              0xF4
#define GSCIS_TAG_REG_DATA_MODEL      0xF5
#define GSCIS_TAG_ACR_TABLE           0xF6
#define GSCIS_TAG_CARD_APDU           0xF7
#define GSCIS_TAG_REDIRECTION         0xFA
#define GSCIS_TAG_CT                  0xFB
#define GSCIS_TAG_ST                  0xFC
#define GSCIS_TAG_NEXTCCC             0xFD

/*** General - EF 2200 ***/
#define GSCIS_TAG_FNAME               0x01
#define GSCIS_TAG_MNAME               0x02
#define GSCIS_TAG_LNAME               0x03
#define GSCIS_TAG_SUFFIX              0x04
#define GSCIS_TAG_GOVT_AGENCY         0x05
#define GSCIS_TAG_BUREAU              0x06
#define GSCIS_TAG_BUREAU_CODE         0x07
#define GSCIS_TAG_DEPT_CODE           0x08
#define GSCIS_TAG_TITLE               0x09
#define GSCIS_TAG_BUILDING            0x10
#define GSCIS_TAG_OFFICE_ADDR1        0x11
#define GSCIS_TAG_OFFICE_ADDR2        0x12
#define GSCIS_TAG_OFFICE_CITY         0x13
#define GSCIS_TAG_OFFICE_STATE        0x14
#define GSCIS_TAG_OFFICE_ZIP          0x15
#define GSCIS_TAG_OFFICE_COUNTRY      0x16
#define GSCIS_TAG_OFFICE_PHONE        0x17
#define GSCIS_TAG_OFFICE_PHONE_EXT    0x18
#define GSCIS_TAG_OFFICE_FAX          0x19
#define GSCIS_TAG_OFFICE_EMAIL        0x1A
#define GSCIS_TAG_OFFICE_ROOM         0x1B
#define GSCIS_TAG_NONGOV_AGENCY       0x1C
#define GSCIS_TAG_SSN_DESIGNATOR      0x1D

/*** PII - EF 2100 ***/
#define GSCIS_TAG_SSN                 0x20
#define GSCIS_TAG_DOB                 0x21
#define GSCIS_TAG_GENDER              0x22

/*** Login Information - EF 4000 ***/
#define GSCIS_TAG_USERID              0x40
#define GSCIS_TAG_DOMAIN              0x41
#define GSCIS_TAG_PASSWORD            0x42

/*** Card Information - EF 5000 ***/
#define GSCIS_TAG_ISSUERID            0x50
#define GSCIS_TAG_SERNO               0x51
#define GSCIS_TAG_ISSUE_DATE          0x52
#define GSCIS_TAG_EXPIRE_DATE         0x53
#define GSCIS_TAG_CARD_TYPE           0x54
#define GSCIS_TAG_SECURITY_CODE       0x57
#define GSCIS_TAG_CARDID_AID          0x58

/*** PKI Information - EF 7000 ***/
#define GSCIS_TAG_CERTIFICATE         0x70
#define GSCIS_TAG_CERT_ISSUE_DATE     0x71
#define GSCIS_TAG_CERT_EXPIRE_DATE    0x72

/** Applet IDs **/
#define GSCIS_AID_CCC                 0xA0, 0x00, 0x00, 0x01, 0x16, 0xDB, 0x00

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

static const char *CACKEY_DEBUG_FUNC_TAG_TO_STR(unsigned char tag) {
	switch (tag) {
		case GSCIS_TAG_CARDID:
			return("GSCIS_TAG_CARDID");
		case GSCIS_TAG_CCC_VER:
			return("GSCIS_TAG_CCC_VER");
		case GSCIS_TAG_CCG_VER:
			return("GSCIS_TAG_CCG_VER");
		case GSCIS_TAG_CARDURL:
			return("GSCIS_TAG_CARDURL");
		case GSCIS_TAG_PKCS15:
			return("GSCIS_TAG_PKCS15");
		case GSCIS_TAG_REG_DATA_MODEL:
			return("GSCIS_TAG_REG_DATA_MODEL");
		case GSCIS_TAG_ACR_TABLE:
			return("GSCIS_TAG_ACR_TABLE");
		case GSCIS_TAG_CARD_APDU:
			return("GSCIS_TAG_CARD_APDU");
		case GSCIS_TAG_REDIRECTION:
			return("GSCIS_TAG_REDIRECTION");
		case GSCIS_TAG_CT:
			return("GSCIS_TAG_CT");
		case GSCIS_TAG_ST:
			return("GSCIS_TAG_ST");
		case GSCIS_TAG_NEXTCCC:
			return("GSCIS_TAG_NEXTCCC");
		case GSCIS_TAG_FNAME:
			return("GSCIS_TAG_FNAME");
		case GSCIS_TAG_MNAME:
			return("GSCIS_TAG_MNAME");
		case GSCIS_TAG_LNAME:
			return("GSCIS_TAG_LNAME");
		case GSCIS_TAG_SUFFIX:
			return("GSCIS_TAG_SUFFIX");
		case GSCIS_TAG_GOVT_AGENCY:
			return("GSCIS_TAG_GOVT_AGENCY");
		case GSCIS_TAG_BUREAU:
			return("GSCIS_TAG_BUREAU");
		case GSCIS_TAG_BUREAU_CODE:
			return("GSCIS_TAG_BUREAU_CODE");
		case GSCIS_TAG_DEPT_CODE:
			return("GSCIS_TAG_DEPT_CODE");
		case GSCIS_TAG_TITLE:
			return("GSCIS_TAG_TITLE");
		case GSCIS_TAG_BUILDING:
			return("GSCIS_TAG_BUILDING");
		case GSCIS_TAG_OFFICE_ADDR1:
			return("GSCIS_TAG_OFFICE_ADDR1");
		case GSCIS_TAG_OFFICE_ADDR2:
			return("GSCIS_TAG_OFFICE_ADDR2");
		case GSCIS_TAG_OFFICE_CITY:
			return("GSCIS_TAG_OFFICE_CITY");
		case GSCIS_TAG_OFFICE_STATE:
			return("GSCIS_TAG_OFFICE_STATE");
		case GSCIS_TAG_OFFICE_ZIP:
			return("GSCIS_TAG_OFFICE_ZIP");
		case GSCIS_TAG_OFFICE_COUNTRY:
			return("GSCIS_TAG_OFFICE_COUNTRY");
		case GSCIS_TAG_OFFICE_PHONE:
			return("GSCIS_TAG_OFFICE_PHONE");
		case GSCIS_TAG_OFFICE_PHONE_EXT:
			return("GSCIS_TAG_OFFICE_PHONE_EXT");
		case GSCIS_TAG_OFFICE_FAX:
			return("GSCIS_TAG_OFFICE_FAX");
		case GSCIS_TAG_OFFICE_EMAIL:
			return("GSCIS_TAG_OFFICE_EMAIL");
		case GSCIS_TAG_OFFICE_ROOM:
			return("GSCIS_TAG_OFFICE_ROOM");
		case GSCIS_TAG_NONGOV_AGENCY:
			return("GSCIS_TAG_NONGOV_AGENCY");
		case GSCIS_TAG_SSN_DESIGNATOR:
			return("GSCIS_TAG_SSN_DESIGNATOR");
		case GSCIS_TAG_SSN:
			return("GSCIS_TAG_SSN");
		case GSCIS_TAG_DOB:
			return("GSCIS_TAG_DOB");
		case GSCIS_TAG_GENDER:
			return("GSCIS_TAG_GENDER");
		case GSCIS_TAG_USERID:
			return("GSCIS_TAG_USERID");
		case GSCIS_TAG_DOMAIN:
			return("GSCIS_TAG_DOMAIN");
		case GSCIS_TAG_PASSWORD:
			return("GSCIS_TAG_PASSWORD");
		case GSCIS_TAG_ISSUERID:
			return("GSCIS_TAG_ISSUERID");
		case GSCIS_TAG_SERNO:
			return("GSCIS_TAG_SERNO");
		case GSCIS_TAG_ISSUE_DATE:
			return("GSCIS_TAG_ISSUE_DATE");
		case GSCIS_TAG_EXPIRE_DATE:
			return("GSCIS_TAG_EXPIRE_DATE");
		case GSCIS_TAG_CARD_TYPE:
			return("GSCIS_TAG_CARD_TYPE");
		case GSCIS_TAG_SECURITY_CODE:
			return("GSCIS_TAG_SECURITY_CODE");
		case GSCIS_TAG_CARDID_AID:
			return("GSCIS_TAG_CARDID_AID");
		case GSCIS_TAG_CERTIFICATE:
			return("GSCIS_TAG_CERTIFICATE");
		case GSCIS_TAG_CERT_ISSUE_DATE:
			return("GSCIS_TAG_CERT_ISSUE_DATE");
		case GSCIS_TAG_CERT_EXPIRE_DATE:
			return("GSCIS_TAG_CERT_EXPIRE_DATE");
	}

	return("UNKNOWN");
}

static const char *CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(LONG retcode) {
	switch (retcode) {
		case SCARD_S_SUCCESS:
			return("SCARD_S_SUCCESS");
		case SCARD_E_CANCELLED:
			return("SCARD_E_CANCELLED");
		case SCARD_E_CANT_DISPOSE:
			return("SCARD_E_CANT_DISPOSE");
		case SCARD_E_INSUFFICIENT_BUFFER:
			return("SCARD_E_INSUFFICIENT_BUFFER");
		case SCARD_E_INVALID_ATR:
			return("SCARD_E_INVALID_ATR");
		case SCARD_E_INVALID_HANDLE:
			return("SCARD_E_INVALID_HANDLE");
		case SCARD_E_INVALID_PARAMETER:
			return("SCARD_E_INVALID_PARAMETER");
		case SCARD_E_INVALID_TARGET:
			return("SCARD_E_INVALID_TARGET");
		case SCARD_E_INVALID_VALUE:
			return("SCARD_E_INVALID_VALUE");
		case SCARD_E_NO_MEMORY:
			return("SCARD_E_NO_MEMORY");
		case SCARD_E_UNKNOWN_READER:
			return("SCARD_E_UNKNOWN_READER");
		case SCARD_E_TIMEOUT:
			return("SCARD_E_TIMEOUT");
		case SCARD_E_SHARING_VIOLATION:
			return("SCARD_E_SHARING_VIOLATION");
		case SCARD_E_NO_SMARTCARD:
			return("SCARD_E_NO_SMARTCARD");
		case SCARD_E_UNKNOWN_CARD:
			return("SCARD_E_UNKNOWN_CARD");
		case SCARD_E_PROTO_MISMATCH:
			return("SCARD_E_PROTO_MISMATCH");
		case SCARD_E_NOT_READY:
			return("SCARD_E_NOT_READY");
		case SCARD_E_SYSTEM_CANCELLED:
			return("SCARD_E_SYSTEM_CANCELLED");
		case SCARD_E_NOT_TRANSACTED:
			return("SCARD_E_NOT_TRANSACTED");
		case SCARD_E_READER_UNAVAILABLE:
			return("SCARD_E_READER_UNAVAILABLE");
		case SCARD_W_UNSUPPORTED_CARD:
			return("SCARD_W_UNSUPPORTED_CARD");
		case SCARD_W_UNRESPONSIVE_CARD:
			return("SCARD_W_UNRESPONSIVE_CARD");
		case SCARD_W_UNPOWERED_CARD:
			return("SCARD_W_UNPOWERED_CARD");
		case SCARD_W_RESET_CARD:
			return("SCARD_W_RESET_CARD");
		case SCARD_W_REMOVED_CARD:
			return("SCARD_W_REMOVED_CARD");
		case SCARD_E_PCI_TOO_SMALL:
			return("SCARD_E_PCI_TOO_SMALL");
		case SCARD_E_READER_UNSUPPORTED:
			return("SCARD_E_READER_UNSUPPORTED");
		case SCARD_E_DUPLICATE_READER:
			return("SCARD_E_DUPLICATE_READER");
		case SCARD_E_CARD_UNSUPPORTED:
			return("SCARD_E_CARD_UNSUPPORTED");
		case SCARD_E_NO_SERVICE:
			return("SCARD_E_NO_SERVICE");
		case SCARD_E_SERVICE_STOPPED:
			return("SCARD_E_SERVICE_STOPPED");
		case SCARD_W_INSERTED_CARD:
			return("SCARD_W_INSERTED_CARD");
		case SCARD_E_UNSUPPORTED_FEATURE:
			return("SCARD_E_UNSUPPORTED_FEATURE");
	}

	return("UNKNOWN");
}

static const char *CACKEY_DEBUG_FUNC_OBJID_TO_STR(uint16_t objid) {
	switch (objid) {
		case 0x2000:
			return("CACKEY_TLV_OBJID_GENERALINFO");
		case 0x2100:
			return("CACKEY_TLV_OBJID_PROPERSONALINFO");
		case 0x3000:
			return("CACKEY_TLV_OBJID_ACCESSCONTROL");
		case 0x4000:
			return("CACKEY_TLV_OBJID_LOGIN");
		case 0x5000:
			return("CACKEY_TLV_OBJID_CARDINFO");
		case 0x6000:
			return("CACKEY_TLV_OBJID_BIOMETRICS");
		case 0x7000:
			return("CACKEY_TLV_OBJID_DIGITALSIGCERT");
		case 0x0200:
			return("CACKEY_TLV_OBJID_CAC_PERSON");
		case 0x0202:
			return("CACKEY_TLV_OBJID_CAC_BENEFITS");
		case 0x0203:
			return("CACKEY_TLV_OBJID_CAC_OTHERBENEFITS");
		case 0x0201:
			return("CACKEY_TLV_OBJID_CAC_PERSONNEL");
		case 0x02FE:
			return("CACKEY_TLV_OBJID_CAC_PKICERT");
	}
	
	return("UNKNOWN");
}

static const char *CACKEY_DEBUG_FUNC_APPTYPE_TO_STR(uint8_t apptype) {
	switch (apptype) {
		case 0x00:
			return("NONE");
		case 0x01:
			return("CACKEY_TLV_APP_GENERIC");
		case 0x02:
			return("CACKEY_TLV_APP_SKI");
		case 0x03:
			return("CACKEY_TLV_APP_GENERIC | CACKEY_TLV_APP_SKI");
		case 0x04:
			return("CACKEY_TLV_APP_PKI");
		case 0x05:
			return("CACKEY_TLV_APP_GENERIC | CACKEY_TLV_APP_PKI");
		case 0x06:
			return("CACKEY_TLV_APP_SKI | CACKEY_TLV_APP_PKI");
		case 0x07:
			return("CACKEY_TLV_APP_GENERIC | CACKEY_TLV_APP_SKI | CACKEY_TLV_APP_PKI");
	}

	return("INVALID");
}

#  define malloc(x) CACKEY_DEBUG_FUNC_MALLOC(x, __func__)
#  define realloc(x, y) CACKEY_DEBUG_FUNC_REALLOC(x, y, __func__)
#else
#  define CACKEY_DEBUG_PRINTF(x...) /**/
#  define CACKEY_DEBUG_PRINTBUF(f, x, y) /**/
#  define CACKEY_DEBUG_PERROR(x) /**/
#  define CACKEY_DEBUG_FUNC_TAG_TO_STR(x) "DEBUG_DISABLED"
#  define CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(x) "DEBUG_DISABLED"
#  define CACKEY_DEBUG_FUNC_OBJID_TO_STR(x) "DEBUG_DISABLED"
#  define CACKEY_DEBUG_FUNC_APPTYPE_TO_STR(x) "DEBUG_DISABLED"
#endif

struct cackey_pcsc_identity {
	unsigned char applet[7];
	uint16_t file;

	unsigned char *label;

	size_t certificate_len;
	unsigned char *certificate;
};

struct cackey_identity {
	struct cackey_pcsc_identity *identity;

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

struct cackey_slot {
	int active;

	char *pcsc_reader;

	int pcsc_card_connected;
	SCARDHANDLE pcsc_card;
};

typedef enum {
	CACKEY_TLV_APP_GENERIC = 0x01,
	CACKEY_TLV_APP_SKI     = 0x02,
	CACKEY_TLV_APP_PKI     = 0x04
} cackey_tlv_apptype;

typedef enum {
	CACKEY_TLV_OBJID_GENERALINFO       = 0x2000,
	CACKEY_TLV_OBJID_PROPERSONALINFO   = 0x2100,
	CACKEY_TLV_OBJID_ACCESSCONTROL     = 0x3000,
	CACKEY_TLV_OBJID_LOGIN             = 0x4000,
	CACKEY_TLV_OBJID_CARDINFO          = 0x5000,
	CACKEY_TLV_OBJID_BIOMETRICS        = 0x6000,
	CACKEY_TLV_OBJID_DIGITALSIGCERT    = 0x7000,
	CACKEY_TLV_OBJID_CAC_PERSON        = 0x0200,
	CACKEY_TLV_OBJID_CAC_BENEFITS      = 0x0202,
	CACKEY_TLV_OBJID_CAC_OTHERBENEFITS = 0x0203,
	CACKEY_TLV_OBJID_CAC_PERSONNEL     = 0x0201,
	CACKEY_TLV_OBJID_CAC_PKICERT       = 0x02FE
} cackey_tlv_objectid;

struct cackey_tlv_cardurl {
	unsigned char        rid[5];
	cackey_tlv_apptype   apptype;
	cackey_tlv_objectid  objectid;
	cackey_tlv_objectid  appid;
	unsigned char        pinid;
};

struct cackey_tlv_entity;
struct cackey_tlv_entity {
	uint8_t tag;
	size_t length;

	union {
		void *value;
		struct cackey_tlv_cardurl *value_cardurl;
		uint8_t value_byte;
	};

	struct cackey_tlv_entity *_next;
};

/* CACKEY Global Handles */
static void *cackey_biglock = NULL;
static struct cackey_session cackey_sessions[128];
static struct cackey_slot cackey_slots[128];
static int cackey_initialized = 0;
static int cackey_biglock_init = 0;
CK_C_INITIALIZE_ARGS cackey_args;

/* PCSC Global Handles */
static LPSCARDCONTEXT cackey_pcsc_handle = NULL;

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

/* PC/SC Related Functions */
static void cackey_slots_disconnect_all(void) {
	uint32_t idx;

	CACKEY_DEBUG_PRINTF("Called.");

	for (idx = 0; idx < (sizeof(cackey_slots) / sizeof(cackey_slots[0])); idx++) {
		if (cackey_slots[idx].pcsc_card_connected) {
			CACKEY_DEBUG_PRINTF("SCardDisconnect(%lu) called", (unsigned long) idx);

			SCardDisconnect(cackey_slots[idx].pcsc_card, SCARD_LEAVE_CARD);
		}

		cackey_slots[idx].pcsc_card_connected = 0;
	}

	CACKEY_DEBUG_PRINTF("Returning");

	return;
}

static int cackey_pcsc_connect(void) {
	LONG scard_est_context_ret;
#ifdef HAVE_SCARDISVALIDCONTEXT
	LONG scard_isvalid_ret;
#endif

	CACKEY_DEBUG_PRINTF("Called.");

	if (cackey_pcsc_handle == NULL) {
		cackey_pcsc_handle = malloc(sizeof(*cackey_pcsc_handle));
		if (cackey_pcsc_handle == NULL) {
			CACKEY_DEBUG_PRINTF("Call to malloc() failed, returning in failure");

			cackey_slots_disconnect_all();

			return(-1);
		}

		CACKEY_DEBUG_PRINTF("SCardEstablishContext() called");
		scard_est_context_ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, cackey_pcsc_handle);
		if (scard_est_context_ret != SCARD_S_SUCCESS) {
			CACKEY_DEBUG_PRINTF("Call to SCardEstablishContext failed (returned %s/%li), returning in failure", CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(scard_est_context_ret), (long) scard_est_context_ret);

			free(cackey_pcsc_handle);

			cackey_slots_disconnect_all();

			return(-1);
		}
	}

#ifdef HAVE_SCARDISVALIDCONTEXT
	CACKEY_DEBUG_PRINTF("SCardIsValidContext() called");
	scard_isvalid_ret = SCardIsValidContext(*cackey_pcsc_handle);
	if (scard_isvalid_ret != SCARD_S_SUCCESS) {
		CACKEY_DEBUG_PRINTF("Handle has become invalid (SCardIsValidContext = %s/%li), trying to re-establish...", CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(scard_isvalid_ret), (long) scard_isvalid_ret);

		CACKEY_DEBUG_PRINTF("SCardEstablishContext() called");
		scard_est_context_ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, cackey_pcsc_handle);
		if (scard_est_context_ret != SCARD_S_SUCCESS) {
			CACKEY_DEBUG_PRINTF("Call to SCardEstablishContext failed (returned %s/%li), returning in failure", CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(scard_est_context_ret), (long) scard_est_context_ret);

			free(cackey_pcsc_handle);

			cackey_slots_disconnect_all();

			return(-1);
		}

		CACKEY_DEBUG_PRINTF("Handle has been re-established");
	}
#endif

	CACKEY_DEBUG_PRINTF("Sucessfully connected to PC/SC, returning in success");

	return(0);
}

/* APDU Related Functions */
/** Le = 0x00 to indicate not to send Le **/
static int cackey_send_apdu(struct cackey_slot *slot, unsigned char class, unsigned char instruction, unsigned char p1, unsigned char p2, unsigned char lc, unsigned char *data, unsigned char le, uint16_t *respcode, unsigned char *respdata, size_t *respdata_len) {
	uint8_t major_rc, minor_rc;
	size_t bytes_to_copy, tmp_respdata_len;
	DWORD protocol;
	DWORD xmit_len, recv_len;
	LONG scard_conn_ret, scard_xmit_ret, scard_reconn_ret;
	BYTE xmit_buf[1024], recv_buf[1024];
	int pcsc_connect_ret, pcsc_getresp_ret;
	int idx;

	CACKEY_DEBUG_PRINTF("Called.");

	if (!slot) {
		CACKEY_DEBUG_PRINTF("Invalid slot specified.");

		return(-1);
	}

	pcsc_connect_ret = cackey_pcsc_connect();
	if (pcsc_connect_ret < 0) {
		CACKEY_DEBUG_PRINTF("Connection to PC/SC failed, returning in failure");

		return(-1);
	}

	/* Connect to reader, if needed */
	if (!slot->pcsc_card_connected) {
		CACKEY_DEBUG_PRINTF("SCardConnect(%s) called", slot->pcsc_reader);
		scard_conn_ret = SCardConnect(*cackey_pcsc_handle, slot->pcsc_reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &slot->pcsc_card, &protocol);

		if (scard_conn_ret != SCARD_S_SUCCESS) {
			CACKEY_DEBUG_PRINTF("Connection to card failed, returning in failure (SCardConnect() = %s/%li)", CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(scard_conn_ret), (long) scard_conn_ret);

			return(-1);
		}

		slot->pcsc_card_connected = 1;
	}

	/* Transmit */
	xmit_len = 0;
	xmit_buf[xmit_len++] = class;
	xmit_buf[xmit_len++] = instruction;
	xmit_buf[xmit_len++] = p1;
	xmit_buf[xmit_len++] = p2;
	if (data) {
		xmit_buf[xmit_len++] = lc;
		for (idx = 0; idx < lc; idx++) {
			xmit_buf[xmit_len++] = data[idx];
		}
	}

	if (le != 0x00) {
		xmit_buf[xmit_len++] = le;
	}

	CACKEY_DEBUG_PRINTBUF("Sending APDU:", xmit_buf, xmit_len);

	recv_len = sizeof(recv_buf);
	scard_xmit_ret = SCardTransmit(slot->pcsc_card, SCARD_PCI_T0, xmit_buf, xmit_len, SCARD_PCI_T1, recv_buf, &recv_len);
	if (scard_xmit_ret != SCARD_S_SUCCESS) {
		CACKEY_DEBUG_PRINTF("Failed to send APDU to card (SCardTransmit() = %s/%lx)", CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(scard_xmit_ret), (unsigned long) scard_xmit_ret);

		if (scard_xmit_ret == SCARD_W_RESET_CARD) {
			CACKEY_DEBUG_PRINTF("Reset required, please hold...");

			scard_reconn_ret = SCardReconnect(slot->pcsc_card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_RESET_CARD, &protocol);
			if (scard_reconn_ret == SCARD_S_SUCCESS) {
				CACKEY_DEBUG_PRINTF("Reset successful, retransmitting");
				scard_xmit_ret = SCardTransmit(slot->pcsc_card, SCARD_PCI_T0, xmit_buf, xmit_len, SCARD_PCI_T0, recv_buf, &recv_len);

				if (scard_xmit_ret != SCARD_S_SUCCESS) {
					CACKEY_DEBUG_PRINTF("Retransmit failed, returning in failure after disconnecting the card (SCardTransmit = %s/%li)", CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(scard_xmit_ret), (long) scard_xmit_ret);

					SCardDisconnect(slot->pcsc_card, SCARD_RESET_CARD);
					slot->pcsc_card_connected = 0;

					return(-1);
				}
			} else {
				CACKEY_DEBUG_PRINTF("Disconnecting card");

				SCardDisconnect(slot->pcsc_card, SCARD_RESET_CARD);
				slot->pcsc_card_connected = 0;

				CACKEY_DEBUG_PRINTF("Returning in failure");
				return(-1);
			}
		} else {
			CACKEY_DEBUG_PRINTF("Disconnecting card");

			SCardDisconnect(slot->pcsc_card, SCARD_RESET_CARD);
			slot->pcsc_card_connected = 0;

			CACKEY_DEBUG_PRINTF("Returning in failure");
			return(-1);
		}
	}

	CACKEY_DEBUG_PRINTBUF("Returned Value:", recv_buf, recv_len);

	if (recv_len < 2) {
		/* Minimal response length is 2 bytes, returning in failure */
		CACKEY_DEBUG_PRINTF("Response too small, returning in failure (recv_len = %lu)", (unsigned long) recv_len);

		return(-1);
	}

	/* Determine result code */
	major_rc = recv_buf[recv_len - 2];
	minor_rc = recv_buf[recv_len - 1];
	if (respcode) {
		*respcode = (major_rc << 8) | minor_rc;
	}

	/* Adjust message buffer */
	recv_len -= 2;

	/* Add bytes to return value */
	tmp_respdata_len = 0;
	if (respdata && respdata_len) {
		tmp_respdata_len = *respdata_len;

		bytes_to_copy = *respdata_len;

		if (recv_len < bytes_to_copy) {
			bytes_to_copy = recv_len;
		}

		CACKEY_DEBUG_PRINTF("Copying %lu bytes to the buffer", (unsigned long) bytes_to_copy);

		memcpy(respdata, recv_buf, bytes_to_copy);
		respdata += bytes_to_copy;

		*respdata_len = bytes_to_copy;
		tmp_respdata_len -= bytes_to_copy;
	} else {
		if (recv_len != 0) {
			CACKEY_DEBUG_PRINTF("Throwing away %lu bytes, nowhere to put them!", (unsigned long) recv_len);
		}
	}

	if (major_rc == 0x61) {
		/* We need to READ */
		CACKEY_DEBUG_PRINTF("Buffer read required");

		pcsc_getresp_ret = cackey_send_apdu(slot, GSCIS_CLASS_ISO7816, GSCIS_INSTR_GET_RESPONSE, 0x00, 0x00, 0, NULL, minor_rc, respcode, respdata, &tmp_respdata_len);
		if (pcsc_getresp_ret < 0) {
			CACKEY_DEBUG_PRINTF("Buffer read failed!  Returning in failure");

			return(-1);
		}

		if (respdata_len) {
			*respdata_len += tmp_respdata_len;
		}

		CACKEY_DEBUG_PRINTF("Returning in success (buffer read complete)");
		return(0);
	}

	if (major_rc == 0x90) {
		/* Success */
		CACKEY_DEBUG_PRINTF("Returning in success (major_rc = 0x90)");

		return(0);
	}


	CACKEY_DEBUG_PRINTF("APDU Returned an error, returning in failure");

	return(-1);
}

static ssize_t cackey_read_buffer(struct cackey_slot *slot, unsigned char *buffer, size_t count, unsigned char t_or_v, size_t initial_offset) {
	size_t offset = 0, max_offset, max_count;
	unsigned char cmd[2];
	uint16_t respcode;
	int send_ret;

	CACKEY_DEBUG_PRINTF("Called.");

	max_offset = count;
	max_count = 252;

	cmd[0] = t_or_v;

	while (1) {
		if (offset >= max_offset) {
			CACKEY_DEBUG_PRINTF("Buffer too small, returning what we got...");

			break;
		}

		count = max_offset - offset;
		if (count > max_count) {
			count = max_count;
		}

		cmd[1] = count;

		send_ret = cackey_send_apdu(slot, GSCIS_CLASS_GLOBAL_PLATFORM, GSCIS_INSTR_READ_BUFFER, ((initial_offset + offset) >> 8) & 0xff, (initial_offset + offset) & 0xff, sizeof(cmd), cmd, 0x00, &respcode, buffer + offset, &count);
		if (send_ret < 0) {
			if (respcode == 0x6A86) {
				if (max_count == 1) {
					break;
				}

				max_count = max_count / 2;

				continue;
			}

			CACKEY_DEBUG_PRINTF("cackey_send_apdu() failed, returning in failure");

			return(-1);
		}

		offset += count;

		if (count < max_count) {
			CACKEY_DEBUG_PRINTF("Short read -- count = %i, cmd[1] = %i", count, cmd[1]);

			break;
		}
	}

	CACKEY_DEBUG_PRINTF("Returning in success, read %lu bytes", (unsigned long) offset);

	return(offset);
}

static int cackey_select_applet(struct cackey_slot *slot, unsigned char *aid, size_t aid_len) {
	int send_ret;

	CACKEY_DEBUG_PRINTF("Called.");

	CACKEY_DEBUG_PRINTBUF("Selecting applet:", aid, aid_len);

	send_ret = cackey_send_apdu(slot, GSCIS_CLASS_ISO7816, GSCIS_INSTR_SELECT, GSCIS_PARAM_SELECT_APPLET, 0x0C, aid_len, aid, 0x00, NULL, NULL, NULL);
	if (send_ret < 0) {
		CACKEY_DEBUG_PRINTF("Failed to open applet, returning in failure");

		return(-1);
	}

	CACKEY_DEBUG_PRINTF("Successfully selected file");

	return(0);
}

static int cackey_select_file(struct cackey_slot *slot, uint16_t ef) {
	unsigned char fid_buf[2];
	int send_ret;

	CACKEY_DEBUG_PRINTF("Called.");

	/* Open the elementary file */
	fid_buf[0] = (ef >> 8) & 0xff;
	fid_buf[1] = ef & 0xff;

	CACKEY_DEBUG_PRINTF("Selecting file: %04lx", (unsigned long) ef);

	send_ret = cackey_send_apdu(slot, GSCIS_CLASS_ISO7816, GSCIS_INSTR_SELECT, 0x02, 0x0C, sizeof(fid_buf), fid_buf, 0x00, NULL, NULL, NULL);
	if (send_ret < 0) {
		CACKEY_DEBUG_PRINTF("Failed to open file, returning in failure");

		return(-1);
	}

	CACKEY_DEBUG_PRINTF("Successfully selected file");

	return(0);
}

static void cackey_free_tlv(struct cackey_tlv_entity *root) {
	struct cackey_tlv_entity *curr, *next;

	if (root == NULL) {
		return;
	}

	for (curr = root; curr; curr = next) {
		next = curr->_next;

		switch (curr->tag) {
			case GSCIS_TAG_ACR_TABLE:
			case GSCIS_TAG_CERTIFICATE:
				if (curr->value) {
					free(curr->value);
				}
				break;
			case GSCIS_TAG_CARDURL:
				if (curr->value_cardurl) {
					free(curr->value_cardurl);
				}
				break;
		}

		free(curr);
	}

	return;
}

static struct cackey_tlv_entity *cackey_read_tlv(struct cackey_slot *slot) {
	struct cackey_tlv_entity *curr_entity, *root = NULL, *last = NULL;
	unsigned char tlen_buf[2], tval_buf[1024], *tval;
	unsigned char vlen_buf[2], vval_buf[8192], *vval;
	unsigned char *tmpbuf;
	ssize_t tlen, vlen;
	ssize_t read_ret;
	size_t offset_t = 0, offset_v = 0;
	unsigned char tag;
	size_t length;

	CACKEY_DEBUG_PRINTF("Called.");

	read_ret = cackey_read_buffer(slot, tlen_buf, sizeof(tlen_buf), 1, offset_t);
	if (read_ret != sizeof(tlen_buf)) {
		CACKEY_DEBUG_PRINTF("Read failed, returning in failure");

		return(NULL);
	}

	tlen = (tlen_buf[1] << 8) | tlen_buf[0];

	read_ret = cackey_read_buffer(slot, vlen_buf, sizeof(vlen_buf), 2, offset_v);
	if (read_ret != sizeof(vlen_buf)) {
		CACKEY_DEBUG_PRINTF("Read failed, returning in failure");

		return(NULL);
	}

	vlen = (vlen_buf[1] << 8) | vlen_buf[0];

	CACKEY_DEBUG_PRINTF("Tag Length = %i, Value Length = %i", tlen, vlen);

	tlen -= 2;
	offset_t += 2;

	vlen -= 2;
	offset_v += 2;

	if (tlen > sizeof(tval_buf)) {
		CACKEY_DEBUG_PRINTF("Tag length is too large, returning in failure");

		return(NULL);
	}

	if (vlen > sizeof(vval_buf)) {
		CACKEY_DEBUG_PRINTF("Value length is too large, returning in failure");

		return(NULL);
	}

	read_ret = cackey_read_buffer(slot, tval_buf, tlen, 1, offset_t);
	if (read_ret != tlen) {
		CACKEY_DEBUG_PRINTF("Unable to read entire T-buffer, returning in failure");

		return(NULL);
	}

	read_ret = cackey_read_buffer(slot, vval_buf, vlen, 2, offset_v);
	if (read_ret != vlen) {
		CACKEY_DEBUG_PRINTF("Unable to read entire V-buffer, returning in failure");

		return(NULL);
	}

	tval = tval_buf;
	vval = vval_buf;
	while (tlen > 0 && vlen > 0) {
		tag = *tval;
		tval++;
		tlen--;

		if (*tval == 0xff) {
			length = (tval[2] << 8) | tval[1];
			tval += 3;
			tlen -= 3;
		} else {
			length = *tval;
			tval++;
			tlen--;
		}

		CACKEY_DEBUG_PRINTF("Tag: %s (%02x)", CACKEY_DEBUG_FUNC_TAG_TO_STR(tag), (unsigned int) tag);
		CACKEY_DEBUG_PRINTBUF("Value:", vval, length);
		vval += length;
		vlen -= length;

		curr_entity = NULL;
		switch (tag) {
			case GSCIS_TAG_CARDURL:
				curr_entity = malloc(sizeof(*curr_entity));
				curr_entity->value_cardurl = malloc(sizeof(*curr_entity->value_cardurl));

				memcpy(curr_entity->value_cardurl->rid, vval, 5);
				curr_entity->value_cardurl->apptype = vval[5];
				curr_entity->value_cardurl->objectid = (vval[6] << 8) | vval[7];
				curr_entity->value_cardurl->appid = (vval[8] << 8) | vval[9];

				curr_entity->tag = tag;
				curr_entity->_next = NULL;

				break;
			case GSCIS_TAG_ACR_TABLE:
				curr_entity = malloc(sizeof(*curr_entity));
				tmpbuf = malloc(length);

				memcpy(tmpbuf, vval, length);

				curr_entity->tag = tag;
				curr_entity->length = length;
				curr_entity->value = tmpbuf;
				curr_entity->_next = NULL;

				break;
			case GSCIS_TAG_CERTIFICATE:
				curr_entity = malloc(sizeof(*curr_entity));
				tmpbuf = malloc(length);

				memcpy(tmpbuf, vval, length);

				curr_entity->tag = tag;
				curr_entity->length = length;
				curr_entity->value = tmpbuf;
				curr_entity->_next = NULL;

				break;
			case GSCIS_TAG_PKCS15:
				curr_entity = malloc(sizeof(*curr_entity));

				curr_entity->tag = tag;
				curr_entity->value_byte = vval[0];
				curr_entity->_next = NULL;

				break;
		}

		if (curr_entity != NULL) {
			if (root == NULL) {
				root = curr_entity;
			}

			if (last != NULL) {
				last->_next = curr_entity;
			}

			last = curr_entity;
		}
	}

	return(root);
}

static void cackey_free_certs(struct cackey_pcsc_identity *start, size_t count, int free_start) {
	size_t idx;

	for (idx = 0; idx < count; idx++) {
		if (start[idx].certificate) {
			free(start[idx].certificate);
		}
	}

	if (free_start) {
		free(start);
	}

	return;
}

static struct cackey_pcsc_identity *cackey_read_certs(struct cackey_slot *slot, struct cackey_pcsc_identity *certs, unsigned long *count) {
	struct cackey_pcsc_identity *curr_id;
	struct cackey_tlv_entity *ccc_tlv, *ccc_curr, *app_tlv, *app_curr;
	unsigned char ccc_aid[] = {GSCIS_AID_CCC};
	unsigned char curr_aid[7];
	unsigned long outidx = 0;
	int certs_resizable;
	int send_ret, select_ret;

	CACKEY_DEBUG_PRINTF("Called.");

	if (count == NULL) {
		CACKEY_DEBUG_PRINTF("count is NULL, returning in failure");

		return(NULL);
	}

	if (*count == 0) {
		if (certs != NULL) {
			CACKEY_DEBUG_PRINTF("Requested we return 0 objects, short-circuit");

			return(certs);
		}
	}

	if (certs == NULL) {
		certs = malloc(sizeof(*certs) * 5);
		*count = 5;
		certs_resizable = 1;
	} else {
		certs_resizable = 0;
	}

	/* Select the CCC Applet */
	send_ret = cackey_select_applet(slot, ccc_aid, sizeof(ccc_aid));
	if (send_ret < 0) {
		CACKEY_DEBUG_PRINTF("Unable to select CCC Applet, returning in failure");

		return(NULL);
	}

	/* Read all the applets from the CCC's TLV */
	ccc_tlv = cackey_read_tlv(slot);

	/* Look for CARDURLs that coorespond to PKI applets */
	for (ccc_curr = ccc_tlv; ccc_curr; ccc_curr = ccc_curr->_next) {
		CACKEY_DEBUG_PRINTF("Found tag: %s ... ", CACKEY_DEBUG_FUNC_TAG_TO_STR(ccc_curr->tag));

		if (ccc_curr->tag != GSCIS_TAG_CARDURL) {
			CACKEY_DEBUG_PRINTF("  ... skipping it (we only care about CARDURLs)");

			continue;
		}

		if ((ccc_curr->value_cardurl->apptype & CACKEY_TLV_APP_PKI) != CACKEY_TLV_APP_PKI) {
			CACKEY_DEBUG_PRINTF("  ... skipping it (we only care about PKI applets, this applet supports: %s/%02x)", CACKEY_DEBUG_FUNC_APPTYPE_TO_STR(ccc_curr->value_cardurl->apptype), (unsigned int) ccc_curr->value_cardurl->apptype);

			continue;
		}

		CACKEY_DEBUG_PRINTBUF("RID:", ccc_curr->value_cardurl->rid, sizeof(ccc_curr->value_cardurl->rid));
		CACKEY_DEBUG_PRINTF("AppID = %s/%04lx", CACKEY_DEBUG_FUNC_OBJID_TO_STR(ccc_curr->value_cardurl->appid), (unsigned long) ccc_curr->value_cardurl->appid);
		CACKEY_DEBUG_PRINTF("ObjectID = %s/%04lx", CACKEY_DEBUG_FUNC_OBJID_TO_STR(ccc_curr->value_cardurl->objectid), (unsigned long) ccc_curr->value_cardurl->objectid);

		memcpy(curr_aid, ccc_curr->value_cardurl->rid, sizeof(ccc_curr->value_cardurl->rid));
		curr_aid[sizeof(curr_aid) - 2] = (ccc_curr->value_cardurl->appid >> 8) & 0xff;
		curr_aid[sizeof(curr_aid) - 1] = ccc_curr->value_cardurl->appid & 0xff;

		/* Select found applet ... */
		select_ret = cackey_select_applet(slot, curr_aid, sizeof(curr_aid));
		if (select_ret < 0) {
			CACKEY_DEBUG_PRINTF("Failed to select applet, skipping processing of this object");

			continue;
		}

		/* ... and object (file) */
		select_ret = cackey_select_file(slot, ccc_curr->value_cardurl->objectid);
		if (select_ret < 0) {
			CACKEY_DEBUG_PRINTF("Failed to select file, skipping processing of this object");

			continue;
		}

		/* Process this file's TLV looking for certificates */
		app_tlv = cackey_read_tlv(slot);

		for (app_curr = app_tlv; app_curr; app_curr = app_curr->_next) {
			CACKEY_DEBUG_PRINTF("Found tag: %s", CACKEY_DEBUG_FUNC_TAG_TO_STR(app_curr->tag));
			if (app_curr->tag != GSCIS_TAG_CERTIFICATE) {
				CACKEY_DEBUG_PRINTF("  ... skipping it (we only care about CERTIFICATEs)");

				continue;
			}

			curr_id = &certs[outidx];
			outidx++;

			memcpy(curr_id->applet, curr_aid, sizeof(curr_id->applet));
			curr_id->file = ccc_curr->value_cardurl->objectid;
			curr_id->label = NULL;

			curr_id->certificate_len = app_curr->length;

			curr_id->certificate = malloc(curr_id->certificate_len);
			memcpy(curr_id->certificate, app_curr->value, curr_id->certificate_len);

			if (outidx >= *count) {
				if (certs_resizable) {
					*count *= 2;
					certs = realloc(certs, sizeof(*certs) * (*count));
				} else {
					break;
				}
			}
		}

		cackey_free_tlv(app_tlv);

		if (outidx >= *count) {
			break;
		}
	}

	cackey_free_tlv(ccc_tlv);

	*count = outidx;

	if (certs_resizable) {
		certs = realloc(certs, sizeof(*certs) * (*count));
	}

	return(certs);
}

/* Returns 1 if a token is in the specified slot, 0 otherwise */
static int cackey_token_present(struct cackey_slot *slot) {
	unsigned char ccc_aid[] = {GSCIS_AID_CCC};
	int send_ret;

	/* Select the CCC Applet */
	send_ret = cackey_select_applet(slot, ccc_aid, sizeof(ccc_aid));
	if (send_ret < 0) {
		return(0);
	}

	return(1);
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

static CK_ATTRIBUTE_PTR cackey_get_attributes(CK_OBJECT_CLASS objectclass, struct cackey_pcsc_identity *identity, unsigned long identity_num, CK_ULONG_PTR pulCount) {
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
	ssize_t certificate_len = -1, x509_read_ret;
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

	for (idx = 0; idx < (sizeof(cackey_slots) / sizeof(cackey_slots[0])); idx++) {
		cackey_slots[idx].active = 0;
		cackey_slots[idx].pcsc_reader = NULL;
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

	cackey_slots_disconnect_all();

	for (idx = 0; idx < (sizeof(cackey_slots) / sizeof(cackey_slots[0])); idx++) {
		if (cackey_slots[idx].pcsc_reader) {
			free(cackey_slots[idx].pcsc_reader);
		}
	}

	cackey_initialized = 0;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo) {
	static CK_UTF8CHAR manufacturerID[] = "U.S. Government";
	static CK_UTF8CHAR libraryDescription[] = "CACKey";

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

/*
 * Process list of readers, and create mapping between reader name and slot ID
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	int mutex_retval;
	int pcsc_connect_ret;
	CK_ULONG count, slot_count = 0, currslot;
	char *pcsc_readers, *pcsc_readers_s, *pcsc_readers_e;
	DWORD pcsc_readers_len;
	LONG scard_listreaders_ret;
	size_t curr_reader_len;

	CACKEY_DEBUG_PRINTF("Called.");

	if (pulCount == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pulCount is NULL.");

		return(CKR_ARGUMENTS_BAD);
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

	/* Clear list of slots */
	if (pSlotList) {
		/* Only update the list of slots if we are actually being supply the slot information */
		cackey_slots_disconnect_all();

		for (currslot = 0; currslot < (sizeof(cackey_slots) / sizeof(cackey_slots[0])); currslot++) {
			if (cackey_slots[currslot].pcsc_reader) {
				free(cackey_slots[currslot].pcsc_reader);

				cackey_slots[currslot].pcsc_reader = NULL;
			}

			cackey_slots[currslot].active = 0;
		}
	}

	/* Determine list of readers */
	pcsc_connect_ret = cackey_pcsc_connect();
	if (pcsc_connect_ret < 0) {
		CACKEY_DEBUG_PRINTF("Connection to PC/SC failed, assuming no slots");

		slot_count = 0;
	} else {
		pcsc_readers_len = 0;

		scard_listreaders_ret = SCardListReaders(*cackey_pcsc_handle, NULL, NULL, &pcsc_readers_len);
		if (scard_listreaders_ret == SCARD_S_SUCCESS && pcsc_readers_len != 0) {
			pcsc_readers = malloc(pcsc_readers_len);
			pcsc_readers_s = pcsc_readers;

			scard_listreaders_ret = SCardListReaders(*cackey_pcsc_handle, NULL, pcsc_readers, &pcsc_readers_len);
			if (scard_listreaders_ret == SCARD_S_SUCCESS) {
				pcsc_readers_e = pcsc_readers + pcsc_readers_len;

				currslot = 0;
				while (pcsc_readers < pcsc_readers_e) {
					curr_reader_len = strlen(pcsc_readers);

					if ((pcsc_readers + curr_reader_len) > pcsc_readers_e) {
						break;
					}

					if (curr_reader_len == 0) {
						break;
					}

					if (currslot >= (sizeof(cackey_slots) / sizeof(cackey_slots[0]))) {
						CACKEY_DEBUG_PRINTF("Found more readers than slots are available!");

						break;
					}

					CACKEY_DEBUG_PRINTF("Found reader: %s", pcsc_readers);

					/* Only update the list of slots if we are actually being supply the slot information */
					if (pSlotList) {
						cackey_slots[currslot].active = 1;
						cackey_slots[currslot].pcsc_reader = strdup(pcsc_readers);
						cackey_slots[currslot].pcsc_card_connected = 0;
					}
					currslot++;

					pcsc_readers += curr_reader_len + 1;
				}

				if (currslot > 0) {
					slot_count = currslot;
				}
			} else {
				CACKEY_DEBUG_PRINTF("Second call to SCardListReaders failed, return %s/%li", CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(scard_listreaders_ret), (long) scard_listreaders_ret);
			}

			free(pcsc_readers_s);
		} else {
			CACKEY_DEBUG_PRINTF("First call to SCardListReaders failed, return %s/%li", CACKEY_DEBUG_FUNC_SCARDERR_TO_STR(scard_listreaders_ret), (long) scard_listreaders_ret);
		}
	}

	mutex_retval = cackey_mutex_unlock(cackey_biglock);
	if (mutex_retval != 0) {
		CACKEY_DEBUG_PRINTF("Error.  Unlocking failed.");

		return(CKR_GENERAL_ERROR);
	}

	if (pSlotList == NULL) {
		*pulCount = slot_count;

		CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

		return(CKR_OK);
	}

	count = *pulCount;
	if (count < slot_count) {
		CACKEY_DEBUG_PRINTF("Error. User allocated %lu entries, but we have %lu entries.", count, slot_count);

		return(CKR_BUFFER_TOO_SMALL);	
	}

	for (currslot = 0; currslot < slot_count; currslot++) {
		pSlotList[currslot] = currslot;
	}

	*pulCount = slot_count;

	CACKEY_DEBUG_PRINTF("Returning CKR_OK (%i)", CKR_OK);

	return(CKR_OK);

	tokenPresent = tokenPresent; /* Supress unused variable warning */
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
	static CK_UTF8CHAR slotDescription[] = "CACKey Slot";
	int bytes_to_copy;

	CACKEY_DEBUG_PRINTF("Called.");

	if (pInfo == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pInfo is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (slotID < 0 || slotID >= (sizeof(cackey_slots) / sizeof(cackey_slots[0]))) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), outside of valid range", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (cackey_slots[slotID].active == 0) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), slot not currently active", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, slotDescription, sizeof(slotDescription) - 1);

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));

	bytes_to_copy = strlen(cackey_slots[slotID].pcsc_reader);
	if (sizeof(pInfo->manufacturerID) < bytes_to_copy) {
		bytes_to_copy = sizeof(pInfo->manufacturerID);
	}
	memcpy(pInfo->manufacturerID, cackey_slots[slotID].pcsc_reader, bytes_to_copy);

	pInfo->flags = 0;

	if (cackey_token_present(&cackey_slots[slotID])) {
		pInfo->flags |= CKF_TOKEN_PRESENT;
	}

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
	static CK_UTF8CHAR model[] = "CAC Token";

	CACKEY_DEBUG_PRINTF("Called.");

	if (pInfo == NULL) {
		CACKEY_DEBUG_PRINTF("Error. pInfo is NULL.");

		return(CKR_ARGUMENTS_BAD);
	}

	if (slotID < 0 || slotID >= (sizeof(cackey_slots) / sizeof(cackey_slots[0]))) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), outside of valid range", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (cackey_slots[slotID].active == 0) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), slot not currently active", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (!cackey_initialized) {
		CACKEY_DEBUG_PRINTF("Error.  Not initialized.");

		return(CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (!cackey_token_present(&cackey_slots[slotID])) {
		CACKEY_DEBUG_PRINTF("No token is present in slotID = %lu", slotID);

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

	pInfo->flags = CKF_WRITE_PROTECTED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

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

	if (slotID < 0 || slotID >= (sizeof(cackey_slots) / sizeof(cackey_slots[0]))) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), outside of valid range", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (cackey_slots[slotID].active == 0) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), slot not currently active", slotID);

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
	struct cackey_pcsc_identity *pcsc_identities;
	struct cackey_identity *identities;
	unsigned long idx, num_ids, id_idx, curr_id_type;
	unsigned long num_certs, cert_idx;
	int mutex_retval;
	int found_session = 0;

	CACKEY_DEBUG_PRINTF("Called.");

	if (slotID < 0 || slotID >= (sizeof(cackey_slots) / sizeof(cackey_slots[0]))) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), outside of valid range", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (cackey_slots[slotID].active == 0) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), slot not currently active", slotID);

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
	if (!cackey_token_present(&cackey_slots[slotID])) {
		CACKEY_DEBUG_PRINTF("Error.  Card not present.  Returning CKR_DEVICE_REMOVED");

		return(CKR_DEVICE_REMOVED);
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

			pcsc_identities = cackey_read_certs(&cackey_slots[slotID], NULL, &num_certs);
			if (pcsc_identities != NULL) {
				/* Convert number of IDs to number of objects */
				num_ids = (CKO_PRIVATE_KEY - CKO_CERTIFICATE + 1) * num_certs;

				identities = malloc(num_ids * sizeof(*identities));

				id_idx = 0;
				for (cert_idx = 0; cert_idx < num_certs; cert_idx++) {
					for (curr_id_type = CKO_CERTIFICATE; curr_id_type <= CKO_PRIVATE_KEY; curr_id_type++) {
						identities[id_idx].attributes = cackey_get_attributes(curr_id_type, &pcsc_identities[cert_idx], -1, &identities[id_idx].attributes_count);

						if (identities[id_idx].attributes == NULL) {
							identities[id_idx].attributes_count = 0;
						}

						id_idx++;
					}
				}

				cackey_sessions[idx].identities = identities;
				cackey_sessions[idx].identities_count = num_ids;

				cackey_free_certs(pcsc_identities, num_certs, 1);
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

	if (slotID < 0 || slotID >= (sizeof(cackey_slots) / sizeof(cackey_slots[0]))) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), outside of valid range", slotID);

		return(CKR_SLOT_ID_INVALID);
	}

	if (cackey_slots[slotID].active == 0) {
		CACKEY_DEBUG_PRINTF("Error. Invalid slot requested (%lu), slot not currently active", slotID);

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

