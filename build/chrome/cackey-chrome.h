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

typedef enum {
	CACKEY_CHROME_OK,
	CACKEY_CHROME_ERROR,
	CACKEY_CHROME_NEEDLOGIN,
	CACKEY_CHROME_NEEDPROTECTEDLOGIN
} cackey_chrome_returnType;

int cackey_chrome_listCertificates(struct cackey_certificate **certificates);
void cackey_chrome_freeCertificates(struct cackey_certificate *certificates, int certificatesCount);

cackey_chrome_returnType cackey_chrome_signMessage(struct cackey_certificate *certificate, void *data, unsigned long dataLength, void *destination, unsigned long *destinationLength, char **pinPrompt, const char *pin);

void cackey_chrome_terminate(void);

#  ifdef __cplusplus
}
#  endif

#endif
