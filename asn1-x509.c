/*
 * Basic implementation of ITU-T X.690 (07/2002) for parsing BER encoded
 * X.509 certificates
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef HAVE_STDARG_H
#  include <stdarg.h>
#endif

#include "asn1-x509.h"

struct asn1_object {
	unsigned long tag;
	unsigned long size;
	void *contents;

	unsigned long asn1rep_len;
	void *asn1rep;
};

struct x509_object {
	struct asn1_object wholething;
		struct asn1_object certificate;
			struct asn1_object version;
			struct asn1_object serial_number;
			struct asn1_object signature_algo;
			struct asn1_object issuer;
			struct asn1_object validity;
			struct asn1_object subject;
		struct asn1_object signature;
};

static int _asn1_x509_read_asn1_object(unsigned char *buf, size_t buflen, va_list *args) {
	unsigned char small_object_size;
	unsigned char *buf_p;
	struct asn1_object *outbuf;

	outbuf = va_arg(*args, struct asn1_object *);

	if (outbuf == NULL) {
		return(0);
	}

	if (buflen == 0) {
		return(-1);
	}

	buf_p = buf;

	outbuf->tag = *buf_p;
	buf_p++;
	buflen--;
	if (buflen == 0) {
		return(-1);
	}

	small_object_size = *buf_p;
	buf_p++;
	buflen--;
	if (buflen == 0) {
		return(-1);
	}

	if ((small_object_size & 0x80) == 0x80) {
		outbuf->size = 0;

		for (small_object_size ^= 0x80; small_object_size; small_object_size--) {
			outbuf->size <<= 8;
			outbuf->size += *buf_p;

			buf_p++;
			buflen--;
			if (buflen == 0) {
				break;
			}
		}
	} else {
		outbuf->size = small_object_size;
	}

	if (outbuf->size > buflen) {
		return(-1);
	}

	outbuf->contents = buf_p;
	outbuf->asn1rep_len = outbuf->size + (buf_p - buf);
	outbuf->asn1rep = buf;

	buf_p += outbuf->size;
	buflen -= outbuf->size;

	return(_asn1_x509_read_asn1_object(buf_p, buflen, args));
}

static int asn1_x509_read_asn1_object(unsigned char *buf, size_t buflen, ...) {
	va_list args;
	int retval;

	va_start(args, buflen);

	retval = _asn1_x509_read_asn1_object(buf, buflen, &args);

	va_end(args);

	return(retval);
}

static int asn1_x509_read_object(unsigned char *buf, size_t buflen, struct x509_object *outbuf) {
	int read_ret;

	read_ret = asn1_x509_read_asn1_object(buf, buflen, &outbuf->wholething, NULL);
	if (read_ret != 0) {
		return(-1);
	}

	read_ret = asn1_x509_read_asn1_object(outbuf->wholething.contents, outbuf->wholething.size, &outbuf->certificate, NULL);
	if (read_ret != 0) {
		return(-1);
	}

	read_ret = asn1_x509_read_asn1_object(outbuf->certificate.contents, outbuf->certificate.size, &outbuf->version, &outbuf->serial_number, &outbuf->signature_algo, &outbuf->issuer, &outbuf->validity, &outbuf->subject, NULL);
	if (read_ret != 0) {
		return(-1);
	}

	return(0);
}

ssize_t x509_to_issuer(void *x509_der_buf, size_t x509_der_buf_len, void **outbuf) {
	struct x509_object x509;
	int read_ret;

	read_ret = asn1_x509_read_object(x509_der_buf, x509_der_buf_len, &x509);
	if (read_ret != 0) {
		return(-1);
	}

	if (outbuf) {
		*outbuf = x509.issuer.asn1rep;
	}

	return(x509.issuer.asn1rep_len);
}

ssize_t x509_to_subject(void *x509_der_buf, size_t x509_der_buf_len, void **outbuf) {
	struct x509_object x509;
	int read_ret;

	read_ret = asn1_x509_read_object(x509_der_buf, x509_der_buf_len, &x509);
	if (read_ret != 0) {
		return(-1);
	}

	if (outbuf) {
		*outbuf = x509.subject.asn1rep;
	}

	return(x509.subject.asn1rep_len);
}

ssize_t x509_to_serial(void *x509_der_buf, size_t x509_der_buf_len, void **outbuf) {
	struct x509_object x509;
	int read_ret;

	read_ret = asn1_x509_read_object(x509_der_buf, x509_der_buf_len, &x509);
	if (read_ret != 0) {
		return(-1);
	}

	if (outbuf) {
		*outbuf = x509.serial_number.asn1rep;
	}

	return(x509.serial_number.asn1rep_len);
}
