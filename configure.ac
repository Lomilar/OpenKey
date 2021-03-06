AC_INIT(cackey, 0.7.9) 
AC_CONFIG_HEADERS(config.h)

dnl Locate standard tools
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_AIX
AC_LANG(C)

dnl Determine this platform
DC_CHK_OS_INFO

dnl Determine how to create shared objects on this platform
DC_GET_SHOBJFLAGS

ACX_PTHREAD(, [
	AC_MSG_WARN([Can not figure out how to compile with pthreads support, run-time will likely fail.])
])

dnl Determine how to create static archives on this platform
AC_CHECK_TOOL(AR, ar)
AC_CHECK_TOOL(RANLIB, ranlib)

dnl Determine how to strip executables and remove symbols
DC_FIND_STRIP_AND_REMOVESYMS(libcackey.syms)

dnl Check for all required headers
AC_CHECK_HEADERS(arpa/inet.h inttypes.h stdarg.h stdint.h stdio.h stdlib.h string.h sys/socket.h sys/types.h sys/un.h time.h unistd.h pthread.h zlib.h limits.h,,[
	AC_WARN([Required header missing, compilation will likely fail.])
], [
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#ifdef HAVE_STDARG_H
#  include <stdarg.h>
#endif
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif
#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_TIME_H
#  include <time.h>
#endif
#ifdef HAVE_PTHREAD_H
#  include <pthread.h>
#endif
#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif
#ifdef HAVE_ZLIB_H
#  include <zlib.h>
#endif
])

dnl Check for PC/SC headers and libraries
DC_PCSC

dnl Check for ZLIB libraries
AC_CHECK_LIB(z, uncompress)

dnl Verify that a basic program will compile
AC_CACHE_CHECK([if basic PC/SC program works], cackey_cv_pcsc_works, [
	AC_LINK_IFELSE(
		AC_LANG_PROGRAM([[
#ifdef HAVE_WINTYPES_H
#  include <wintypes.h>
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
#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif
#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif
#ifdef HAVE_ZLIB_H
#  ifdef HAVE_LIBZ
#    include <zlib.h>
#  endif
#endif
		]], [[
			LPSCARDHANDLE hCard;
			SCARDCONTEXT hContext;
			DWORD dwActiveProtocol;
			LONG scard_conn_ret, scard_est_context_ret;

			scard_est_context_ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);

			hCard = NULL;
			scard_conn_ret = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, hCard, &dwActiveProtocol);
		]]), [
			cackey_cv_pcsc_works=okay
		], [
			cackey_cv_pcsc_works=failed
		])
	]
)

if test "$cackey_cv_pcsc_works" = 'failed'; then
	AC_MSG_FAILURE([simple PC/SC program failed])
fi

dnl Option to enable DoD certs on hardware slot
AC_ARG_ENABLE(dod-certs-on-hw-slots, AC_HELP_STRING([--enable-dod-certs-on-hw-slots], [Specify that DoD certificates should be made available on hardware token slots]), [
	dodcertsonhwslots=$enableval
], [
	dodcertsonhwslots=no
])

if ! test "${dodcertsonhwslots}" = 'no'; then
	AC_DEFINE(CACKEY_CARD_SLOT_INCLUDE_EXTRA_CERTS, [1], [Specify that DoD certificates should be made available on hardware token slots])
fi

dnl Option to disable DoD certs entirely
AC_ARG_ENABLE(dod-certs, AC_HELP_STRING([--disable-dod-certs], [Disable including DoD certs entirely.  The user may override this with the CACKEY_EXTRA_CERTS environment variable.]), [
	dodcerts=$enableval
], [
	dodcerts=yes
])

if test "${dodcerts}" = 'no'; then
	AC_DEFINE(CACKEY_NO_EXTRA_CERTS, [1], [Specify that DoD certificates should not be made available])
fi

dnl Option to hard-code a command to run to request a PIN (enabling protected authentication path)
AC_ARG_WITH(pin-command, AC_HELP_STRING([--with-pin-command=<command>], [Specify a command to run to request a PIN from the user.  The user may override this with the CACKEY_PIN_COMMAND environment variable.]), [
	pincommand="${withval}"
], [
	pincommand="no"
])

AC_ARG_WITH(pin-command-x, AC_HELP_STRING([--with-pin-command-x=<command>], [Same as --with-pin-command, but only sets Protected Authentication Path if the DISPLAY environment variable is set]), [
	pincommandxonly="${withval}"
], [
	pincommandxonly="no"
])

if ! test "${pincommand}" = 'no'; then
	AC_DEFINE_UNQUOTED(CACKEY_PIN_COMMAND_DEFAULT, [$pincommand], [Command to run to prompt user for PIN])
fi

if ! test "${pincommandxonly}" = 'no'; then
	AC_DEFINE_UNQUOTED(CACKEY_PIN_COMMAND_XONLY_DEFAULT, [$pincommandxonly], [Command to run to prompt user for PIN only if DISPLAY environment variable is set])
fi

AC_ARG_WITH(readers-include-only, AC_HELP_STRING([--with-readers-include-only=<string>], [Specify a string to match in a reader to include it, all other readers will be excluded.  The user may override this with the CACKEY_READERS_INCLUDE_ONLY environment variable.]), [
	readers_include_only="${withval}"
], [
	readers_include_only="no"
])

AC_ARG_WITH(readers-exclude, AC_HELP_STRING([--with-readers-exclude=<string>], [Specify a string to match in a reader to exclude it, all other readers will be included.  The user may override this with the CACKEY_READERS_EXCLUDE environment variable.]), [
	readers_exclude="${withval}"
], [
	readers_exclude="no"
])

if ! test "${readers_include_only}" = 'no'; then
	AC_DEFINE_UNQUOTED(CACKEY_READERS_INCLUDE_ONLY_DEFAULT, [$readers_include_only], [Substring to match to include readers])
fi

if ! test "${readers_exclude}" = 'no'; then
	AC_DEFINE_UNQUOTED(CACKEY_READERS_EXCLUDE_DEFAULT, [$readers_exclude], [Substring to match to exclude readers])
fi

dnl Set version script, to limit the scope of symbols
DC_SETVERSIONSCRIPT(libcackey.vers, libcackey.syms)

dnl Upate LDFLAGS to include setting the run-time linker path to the same as our compile-time linker
DC_SYNC_RPATH

dnl If we updated LIBOBJS, update SHLIBOBJS -- must be last.
DC_SYNC_SHLIBOBJS

dnl Produce Makefile
AC_OUTPUT(Makefile libcackey.syms)
