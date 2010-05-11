/*
 * GSC-IS (v2.1) Service Call Level Service Provider Module for PC/SC Lite and
 * DoD CAC/CACv2/PIV/PIVv2 Cards
 */

/* Access ... ? */
#define BSI_AM_XAUTH                 0x02
#define BSI_AM_SECURE_CHANNEL_GP     0x04
#define BSI_AM_PIN                   0x06
#define BSI_AM_SECURE_CHANNEL_ISO    0x0B

/* Access Control Rules */
#define BSI_ACR_ALWYS                0x00
#define BSI_ACR_NEVER                0x01
#define BSI_ACR_XAUTH                0x02
#define BSI_ACR_XAUTH_OR_PIN         0x03
#define BSI_SECURE_CHANNEL_GP        0x04 /* typo in spec? */
#define BSI_ACR_SECURE_CHANNEL_GP    0x04
#define BSI_ACR_PIN_ALWAYS           0x05
#define BSI_ACR_PIN                  0x06
#define BSI_ACR_XAUTH_THEN_PIN       0x07
#define BSI_ACR_UPDATE_ONCE          0x08
#define BSI_ACR_PIN_THEN_XAUTH       0x09
#define BSI_SECURE_CHANNEL_ISO       0x0B /* typo in spec? */
#define BSI_ACR_SECURE_CHANNEL_ISO   0x0B
#define BSI_ACR_XAUTH_AND_PIN        0x0C

/* Algorithms */
#define BSI_CKM_DES3_ECB             0x81
#define BSI_CKM_DES3_CBC             0x82
#define BSI_CKM_RSA_NO_PAD           0xA3

/* Return Codes */
#define BSI_OK                       0x00
#define BSI_ACCESS_DENIED            0x01
#define BSI_ACR_NOT_AVAILABLE        0x02
#define BSI_BAD_AID                  0x03
#define BSI_BAD_ALGO_ID              0x04
#define BSI_BAD_AUTH                 0x05
#define BSI_BAD_HANDLE               0x06
#define BSI_BAD_PARAM                0x07
#define BSI_BAD_TAG                  0x08
#define BSI_CARD_ABSENT              0x09
#define BSI_CARD_REMOVED             0x0A
#define BSI_NO_SPSSERVICE            0x0B
#define BSI_IO_ERROR                 0x0C
#define BSI_INSUFFICIENT_BUFFER      0x0E
#define BSI_NO_CARDSERVICE           0x0F
#define BSI_NO_MORE_SPACE            0x10
#define BSI_PIN_BLOCKED              0x11
#define BSI_TAG_EXISTS               0x13
#define BSI_TIMEOUT_ERROR            0x14
#define BSI_TERMINAL_AUTH            0x15
#define BSI_NO_TEXT_AVAILABLE        0x16
#define BSI_UNKNOWN_ERROR            0x17
#define BSI_UNKNOWN_READER           0x18
#define BSI_SC_LOCKED                0x19
#define BSI_NOT_TRANSACTED           0x20

#define MaxNbAM 50

struct BSIAcr {
	unsigned long ACRType;
	unsigned long keyIDOrReference[MaxNbAM];
	unsigned long AuthNb;
	unsigned long ACRID;
};

struct GCacr {
	struct BSIAcr createACR;
	struct BSIAcr deleteACR;
	struct BSIAcr readTagListACR;
	struct BSIAcr readValueACR;
	struct BSIAcr updateValueACR;
};

struct GCContainerSize {
	unsigned long maxNbDataItems;
	unsigned long maxValueStorageSize;
	
};

struct CRYPTOacr {
	struct BSIAcr getChallengeACR;
	struct BSIAcr internalAuthenticateACR;
	struct BSIAcr pkiComputeACR;
	struct BSIAcr createACR;
	struct BSIAcr deleteACR;
	struct BSIAcr readTagListACR;
	struct BSIAcr readValueACR;
	struct BSIAcr updateValueACR;
};

struct BSIAuthenticator {
};

unsigned long gscBsiUtilAcquireContext(unsigned long hCard, unsigned char *AID, struct BSIAuthenticator strctAuthenticator[], unsigned long authNb);
unsigned long gscBsiUtilConnect(unsigned char *readerName, unsigned long *hCard);
unsigned long gscBsiUtilDisconnect(unsigned long hCard);
unsigned long gscBsiUtilBeginTransaction(unsigned long hCard, _Bool blType);
unsigned long gscBsiUtilEndTransaction(unsigned long hCard);
unsigned long gscBsiUtilGetVersion(unsigned char **version);
unsigned long gscBsiUtilGetCardProperties(unsigned long hCard, unsigned char **CCCUniqueID, unsigned long *cardCapability);
unsigned long gscBsiUtilGetCardStatus(unsigned long hCard);
unsigned long gscBsiUtilGetExtendedErrorText(unsigned long hCard, unsigned char **errorText);
unsigned long gscBsiUtilGetReaderList(unsigned char ***readerList);
unsigned long gscBsiUtilPassthru(unsigned long hCard, unsigned char *cardCommand, unsigned char **cardResponse);
unsigned long gscBsiUtilReleaseContext(unsigned long hCard, unsigned char *AID);
unsigned long gscBsiGcDataCreate(unsigned long hCard, unsigned char *AID, unsigned char tag, unsigned char *value);
unsigned long gscBsiGcDataDelete(unsigned long hCard, unsigned char *AID, unsigned char tag);
unsigned long gscBsiGcGetContainerProperties(unsigned long hCard, unsigned char *AID, struct GCacr *strctGCacr, struct GCContainerSize *strctContainerSizes, unsigned char **containerVersion);
unsigned long gscBsiGcReadTagList(unsigned long hCard, unsigned char *AID, unsigned char **tagArray);
unsigned long gscBsiGcReadValue(unsigned long hCard, unsigned char *AID, unsigned char tag, unsigned char **value);
unsigned long gscBsiGcUpdateValue(unsigned long hCard, unsigned char *AID, unsigned char tag, unsigned char *value);
unsigned long gscBsiGetChallenge(unsigned long hCard, unsigned char *AID, unsigned char **challenge);
unsigned long gscBsiSkiInternalAuthenticate(unsigned long hCard, unsigned char *AID, unsigned char algoID, unsigned char *challenge, unsigned char **cryptogram);
unsigned long gscBsiPkiCompute(unsigned long hCard, unsigned char *AID, unsigned char algoID, unsigned char *message, unsigned char **result);
unsigned long gscBsiPkiGetCertificate(unsigned long hCard, unsigned char *AID, unsigned char **Certificate);
unsigned long gscBsiGetCryptoProperties(unsigned long hCard, unsigned char *AID, struct CRYPTOacr *strctCRYPTOacr, unsigned long *keyLen);
