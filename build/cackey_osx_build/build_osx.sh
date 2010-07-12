#!/bin/bash
# Shell Script to make Mac OS X Releases of CACKey
# Kenneth Van Alstyne
# kenneth.l.vanalstyne@usace.army.mil
# 20100711

# Usage function
usage() {
	echo "Usage: build_osx.sh <target>"
	echo Where target is one of:
	echo "    panther  - (Builds 10.3 Library for PPCG3)"
	echo "    tiger  - (Builds Universal 10.4 Library for PPCG3/i386)"
	echo "    leopard  - (Builds Universal 10.5 Library for PPCG4/i386)"
	echo "    snowleopard  - (Builds Universal 10.6 Library for i386/x86_64)"
	echo "    all - (Builds for all supported targets)"
	echo "    clean - (Cleans up)"
	echo "Run from CACKey Build Root."
	echo "CACKey Build Root Directory MUST be named 'cackey'"
	exit $?
}

# Clean up function
clean() {
	rm -rf macbuild
	make distclean
}

# Directory creation function
makedir() {
	if [ ! -d macbuild ]; then
		mkdir macbuild
		mkdir macbuild/Panther
		mkdir macbuild/Tiger
		mkdir macbuild/Leopard
		mkdir macbuild/SnowLeopard
		mkdir macbuild/pkg
	fi
}

# Build function for Panther
panther() {
	makedir
	HEADERS=/Developer/SDKs/MacOSX10.3.9.sdk/System/Library/Frameworks/PCSC.framework/Versions/A/Headers/
	LIBRARY=/Developer/SDKs/MacOSX10.3.9.sdk/System/Library/Frameworks/PCSC.framework/PCSC
	OSX=Panther
	HOST=powerpc-apple-darwin7
	make distclean
	ARCH="ppc -mcpu=G3"
	CFLAGS="-arch ${ARCH}" ./configure --with-pcsc-headers=${HEADERS} --with-pcsc-libs=${LIBRARY} --host=${HOST}
	make
	cp libcackey.dylib macbuild/${OSX}/libcackey.dylib
	cp libcackey_g.dylib macbuild/${OSX}/libcackey_g.dylib
	pkgbuild
}

# Build function for Tiger
tiger() {
	makedir
	HEADERS=/Developer/SDKs/MacOSX10.4u.sdk/System/Library/Frameworks/PCSC.framework/Versions/A/Headers/
	LIBRARY=/Developer/SDKs/MacOSX10.4u.sdk/System/Library/Frameworks/PCSC.framework/PCSC
	LIB=""
	ARCHLIST=""
	DLIB=""
	DARCHLIST=""
	OSX=Tiger
	for HOST in powerpc-apple-darwin8 i386-apple-darwin8; do
		genbuild
	done
	libbuild
	pkgbuild
}

# Build function for Leopard
leopard() {
	makedir
	HEADERS=/Developer/SDKs/MacOSX10.5.sdk/System/Library/Frameworks/PCSC.framework/Versions/A/Headers/
	LIBRARY=/Developer/SDKs/MacOSX10.5.sdk/System/Library/Frameworks/PCSC.framework/PCSC
	LIB=""
	ARCHLIST=""
	DLIB=""
	DARCHLIST=""
	OSX=Leopard
	for HOST in powerpc-apple-darwin9 i386-apple-darwin9; do
		genbuild
	done
	libbuild
	pkgbuild
}

# Build function for Snow Leopard
snowleopard() {
	makedir
	HEADERS=/Developer/SDKs/MacOSX10.6.sdk/System/Library/Frameworks/PCSC.framework/Versions/A/Headers/
	LIBRARY=/Developer/SDKs/MacOSX10.6.sdk/System/Library/Frameworks/PCSC.framework/PCSC
	LIB=""
	ARCHLIST=""
	DLIB=""
	DARCHLIST=""
	OSX=SnowLeopard
	for HOST in i386-apple-darwin10 x86_64-apple-darwin10; do
		genbuild
	done
	libbuild
	pkgbuild
}

# Generic build function
genbuild() {
	make distclean
	ARCH=`echo ${HOST} | cut -d "-" -f 1`
	if [ ${ARCH} == "powerpc" ]; then
		if [ ${OSX} == "Leopard" ]; then
			ARCH="ppc -mcpu=G4"
		else
			ARCH="ppc -mcpu=G3"
		fi
	fi
	CFLAGS="-arch ${ARCH}" ./configure --with-pcsc-headers=${HEADERS} --with-pcsc-libs=${LIBRARY} --host=${HOST}
	make
	cp libcackey.dylib macbuild/${OSX}/libcackey.dylib.`echo ${ARCH} | cut -d ' ' -f 1`
	cp libcackey_g.dylib macbuild/${OSX}/libcackey_g.dylib.`echo ${ARCH} | cut -d ' ' -f 1` 
}

# Library build function
libbuild() {
	for LIB in macbuild/${OSX}/libcackey.dylib.*; do
		ARCHLIST="${ARCHLIST} `echo '-arch '` `echo ${LIB} | cut -d . -f 3` `echo ' '` `echo ${LIB}`"
	done
	lipo -create ${ARCHLIST} -output macbuild/${OSX}/libcackey.dylib
	for DLIB in macbuild/${OSX}/libcackey_g.dylib.*; do
		DARCHLIST="${DARCHLIST} `echo '-arch '` `echo ${DLIB} | cut -d . -f 3` `echo ' '` `echo ${DLIB}`"
	done
	lipo -create ${DARCHLIST} -output macbuild/${OSX}/libcackey_g.dylib
	rm macbuild/${OSX}/libcackey*.dylib.*
}

# Function to build Mac OS X Packages
pkgbuild() {
	if [ ${OSX} == "Panther" ]; then
		EXT=mpkg
	else
		EXT=pkg
	fi
	/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker -d build/cackey_osx_build/${OSX}_pmbuild.pmdoc -o macbuild/pkg/CACKey_${OSX}.${EXT}
	tar --create --directory macbuild/pkg/ --file macbuild/pkg/CACKey_${OSX}.${EXT}.tar CACKey_${OSX}.${EXT}
	gzip -9 macbuild/pkg/CACKey_${OSX}.${EXT}.tar
	rm -rf macbuild/pkg/CACKey_${OSX}.${EXT}
	echo "${OSX} build complete"
}

# Take command line arguments and execute
case "$1" in
	"")
		usage
		exit $?
	;;

	"panther")
		panther
		exit $?
	;;

	"tiger")
		tiger
		exit $?
	;;

	"leopard")
		leopard
		exit $?
	;;

	"snowleopard")
		snowleopard
		exit $?
	;;

	"all")
		panther
		tiger
		leopard
		snowleopard
		exit $?
	;;

	"clean")
		clean
		exit $?
	;;

	*)
		usage
		exit $?
	;;
esac 
