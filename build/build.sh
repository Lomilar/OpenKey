#! /bin/sh

find . -type f -name '.*.sw?' | xargs rm -f
find . -type f -name '.nfs*' | xargs rm -f

./autogen.sh || exit 1

if [ ! -x configure ]; then
	exit 1
fi

rm -rf autom4te.cache vpn/nrlssc/vpngui/build/

for basefile in install-sh config.sub config.guess; do
	for path in /usr/share/automake-*; do
		file="${path}/${basefile}"
		if [ -f "${file}" ]; then
			cp "${file}" .
			chmod 755 "./${basefile}"

			break
		fi
	done
done
