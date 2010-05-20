AC_INIT(cackey, 0.5.2) 
AC_CONFIG_HEADERS(config.h)

dnl Locate standard tools
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_AIX

dnl Determine this platform
DC_CHK_OS_INFO

dnl Determine how to create shared objects on this platform
DC_GET_SHOBJFLAGS

ACX_PTHREAD(, [
	AC_WARN([Can't figure out how to compile with pthreads support, run-time will likely fail.])
])

dnl Determine how to create static archives on this platform
AC_CHECK_TOOL(AR, ar)
AC_CHECK_TOOL(RANLIB, ranlib)

dnl Determine how to strip executables
AC_CHECK_TOOL(STRIP, strip)

dnl Check for all required headers
AC_CHECK_HEADERS(arpa/inet.h inttypes.h stdarg.h stdint.h stdio.h stdlib.h string.h sys/socket.h sys/types.h sys/un.h unistd.h pthread.h zlib.h limits.h,,[
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

dnl Set version script, to limit the scope of symbols
DC_SETVERSIONSCRIPT(libcackey.vers)

dnl Upate LDFLAGS to include setting the run-time linker path to the same as our compile-time linker
DC_SYNC_RPATH

dnl If we updated LIBOBJS, update SHLIBOBJS -- must be last.
DC_SYNC_SHLIBOBJS

dnl Produce Makefile
AC_OUTPUT(Makefile)
