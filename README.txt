Description:
	CACKey provides a standard interface (PKCS#11) for smartcards connected
	to a PC/SC compliant reader.  It performs a similar function to
	"CoolKey", but only supports Government Smartcards.  It supports all
	Government Smartcards that implement the Government Smartcard
	Interoperability Specification (GSC-IS) v2.1 or newer.  

Compiling:
	$ ./configure
	$ make
	# make install

	This will install two libraries (libcackey.so, and libcackey_g.so) into
	"/usr/local/lib".

Usage:
	The libraries "libcackey.so" and "libcackey_g.so" are RSA PKCS#11
	Providers.  They are meant to be linked into any application that
	requires a PKCS#11 provider.

	The library "libcackey.so" is meant for general purpose use.

	The library "libcackey_g.so" is for debugging purposes.  It has
	debugging symbols compiled in and generates debugging information on
	stderr.

Testing:
	$ make test
	$ ./test
	 - or -
	$ ./test 2>cackey_debug.log
