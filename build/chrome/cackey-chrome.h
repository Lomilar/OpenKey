#ifndef CACKEY_CHROME_CACKEY_H
#define CACKEY_CHROME_CACKEY_H 1

#  ifdef __cplusplus
extern "C" {
#  endif

#include <stddef.h>

struct cackey_certificate {
	size_t certificate_len;
	void *certificate;
};

struct cackey_reader {
	char *reader;
	bool cardInserted;
};

typedef enum {
	CACKEY_CHROME_OK,
	CACKEY_CHROME_ERROR,
	CACKEY_CHROME_NEEDLOGIN,
	CACKEY_CHROME_NEEDPROTECTEDLOGIN
} cackey_chrome_returnType;

int cackey_chrome_listCertificates(struct cackey_certificate **certificates);
void cackey_chrome_freeCertificates(struct cackey_certificate *certificates, int certificatesCount);

int cackey_chrome_listReaders(struct cackey_reader **readers);
void cackey_chrome_freeReaders(struct cackey_reader *readers, int readersCount);

cackey_chrome_returnType cackey_chrome_signMessage(struct cackey_certificate *certificate, void *data, unsigned long dataLength, void *destination, unsigned long *destinationLength, char **pinPrompt, const char *pin);

cackey_chrome_returnType cackey_chrome_decryptMessage(struct cackey_certificate *certificate, void *data, unsigned long dataLength, void *destination, unsigned long *destinationLength, char **pinPrompt, const char *pin);

void cackey_chrome_terminate(void);

#  ifdef __cplusplus
}
#  endif

#endif
