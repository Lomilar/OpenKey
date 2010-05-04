#! /bin/sh

rm -f aclocal.m4

make -C aclocal
autoconf; autoheader

rm -rf autom4te.cache/
