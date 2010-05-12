#ifndef USACEIT_ASN1_X509_H
#define USACEIT_ASN1_X509_H 1

#ifdef HAVE_CONFIG_H
#  include "config.h"
#  ifdef HAVE_UNISTD_H
#    include <unistd.h>
#  endif
#else
#  include <unistd.h>
#endif

ssize_t x509_to_subject(void *x509_der_buf, size_t x509_der_buf_len, void **outbuf);

ssize_t x509_to_issuer(void *x509_der_buf, size_t x509_der_buf_len, void **outbuf);

ssize_t x509_to_serial(void *x509_der_buf, size_t x509_der_buf_len, void **outbuf);

#endif
