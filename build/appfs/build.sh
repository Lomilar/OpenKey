#! /bin/bash

set -e

make distclean || true

case "$(uname -m)" in
	i?86)
		ARCH=ix86
		;;
	x86_64)
		ARCH=x86-64
		;;
	*)
		echo "Unknown arch"
		exit 1
		;;
esac

gcc_default_headers_c="$(echo '' | ${CPP:-cpp} -v 2>&1 | sed '/^End of search list/,$ d;0,/search starts here:$/ d' | grep '/gcc/' | sed 's@^ *@-isystem @' | tr $'\n' ' ')"
glibcdir="$(readlink -f /opt/appfs/core.appfs.rkeene.org/glibc/platform/latest)"

./configure \
	--with-pcsc-headers=/opt/appfs/rkeene.org/pcsc-lite/platform/latest/include/PCSC \
	--with-pcsc-libs="-L$(readlink -f /opt/appfs/rkeene.org/pcsc-lite/platform/latest/lib) -Wl,-rpath,$(readlink -f /opt/appfs/rkeene.org/pcsc-lite/platform/latest/lib) -lpcsclite" \
	CC="${CC:-gcc} -nostdinc ${gcc_default_headers_c} -isystem ${glibcdir}/include -isystem /opt/appfs/core.appfs.rkeene.org/linux-headers/platform/2.6.32.63/include" \
	CPPFLAGS="-I/opt/appfs/core.appfs.rkeene.org/zlib/platform/latest/include" \
	LDFLAGS="-L${glibcdir}/lib -L$(readlink -f /opt/appfs/core.appfs.rkeene.org/zlib/platform/latest/lib) -pthread -Wl,--dynamic-linker,${glibcdir}/lib/ld-linux-${ARCH}.so.2"

make
