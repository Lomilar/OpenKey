CC       = pnacl-clang
CXX      = pnacl-clang++
AR       = pnacl-ar
RANLIB   = pnacl-ranlib
FINALIZE = pnacl-finalize

CACKEY_LIBS = -Llib -lcackey -lz
PCSC_LIBS   = -Llib -lpcsc -L${NACL_SDK_ROOT}/lib/pnacl/Release -lppapi -lppapi_cpp
LIBS        = $(CACKEY_LIBS) $(PCSC_LIBS)
CFLAGS      = -Wall -I${NACL_SDK_ROOT}/include
CXXFLAGS    = $(CFLAGS)

PATH += :${NACL_SDK_ROOT}/toolchain/linux_pnacl/bin
export PATH

all: cackey.pexe cackey.nmf

cackey.pexe: cackey-chrome.o cackey-chrome-init.o lib/libcackey.a lib/libpcsc.a lib/libz.a
	$(CXX) -o cackey.pexe.new cackey-chrome.o cackey-chrome-init.o $(LIBS)
	$(FINALIZE) cackey.pexe.new
	mv cackey.pexe.new cackey.pexe

cackey.nmf: cackey.pexe
	${NACL_SDK_ROOT}/tools/create_nmf.py cackey.pexe > cackey.nmf.new
	mv cackey.nmf.new cackey.nmf

lib/libcackey.a: build-deps
	mkdir -p lib
	rm -f lib/libcackey.a
	rm -rf workdir-*
	./build-deps
	cd lib && ln -s ../workdir-*.inst/lib/libcackey.a .
	touch lib/libcackey.a

lib/libpcsc.a: lib/libcackey.a
	mkdir -p lib
	rm -f lib/libpcsc.a
	cd lib && ln -s ../workdir-*.inst/lib/libpcsc.a .
	touch lib/libpcsc.a

lib/libz.a: lib/libcackey.a
	mkdir -p lib
	rm -f lib/libz.a
	cd lib && ln -s ../workdir-*.inst/lib/libz.a .
	touch lib/libz.a

cackey-chrome.o: cackey-chrome.c
cackey-chrome-init.o: cackey-chrome-init.cc

clean:
	rm -rf workdir-*
	rm -f lib/libcackey.a lib/libpcsc.a lib/libz.a
	-rmdir lib
	rm -f cackey-chrome.o cackey-chrome-init.o
	rm -f cackey.pexe

distclean: clean

.PHONY: all clean distclean
