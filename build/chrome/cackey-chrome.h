#ifndef CACKEY_CHROME_CACKEY_H
#define CACKEY_CHROME_CACKEY_H 1

#  ifdef __cplusplus
extern "C" {
#  endif

#include <stddef.h>

struct cackey_certificate {
	size_t certificate_len;
	unsigned char *certificate;
};

int cackey_chrome_listCertificates(struct cackey_certificate **certificates);

#  ifdef __cplusplus
}
#  endif

#endif
