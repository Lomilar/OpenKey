AC_DEFUN(DC_PCSC_HEADERS, [
	SAVE_CFLAGS="${CFLAGS}"
	SAVE_CPPFLAGS="${CPPFLAGS}"
	ADD_CFLAGS=""
	ADD_CPPFLAGS=""

	for headerpath in /usr/include /usr/local/include /usr/cac/include; do
		for subdir in smartcard PCSC pcsc pcsclite ""; do
			headerdir="${headerpath}/${subdir}"
			CFLAGS="${SAVE_CFLAGS} -I${headerdir}"
			CPPFLAGS="${SAVE_CPPFLAGS} -I${headerdir}"

			unset ac_cv_header_pcsclite_h
			unset ac_cv_header_winscard_h

			AC_CHECK_HEADER(pcsclite.h, [
				AC_DEFINE(HAVE_PCSCLITE_H, [1], [Define if you have the PCSC-Lite header file (you should)])

				ADD_CFLAGS=" -I${headerdir}"
				ADD_CPPFLAGS=" -I${headerdir}"

				break
			])

			AC_CHECK_HEADER(winscard.h, [
				AC_DEFINE(HAVE_WINSCARD_H, [1], [Define if you have the PCSC-Lite header file (you should)])

				ADD_CFLAGS=" -I${headerdir}"
				ADD_CPPFLAGS=" -I${headerdir}"

				break
			])
		done

		if test -n "${ADD_CFLAGS}" -o -n "${ADD_CPPFLAGS}"; then
			break
		fi
	done

	CFLAGS="${SAVE_CFLAGS}${ADD_CFLAGS}"
	CPPFLAGS="${SAVE_CPPFLAGS}${ADD_CPPFLAGS}"

	unset ac_cv_header_winscard_h
	AC_CHECK_HEADER(winscard.h, [
		AC_DEFINE(HAVE_WINSCARD_H, [1], [Define if you have the PCSC-Lite header file (you should)])
	], [
		AC_MSG_WARN([unable to find winscard.h from PC/SC, compilation will likely fail.])
	])
])

AC_DEFUN(DC_PCSC_LIBS, [
	foundlib="0"
	for lib in pcsclite pcsc-lite pcsc; do
		AC_CHECK_LIB(${lib}, SCardEstablishContext, [
			LIBS="${LIBS} -l${lib}"

			foundlib="1"

			break
		])
	done

	if test "${foundlib}" = "0"; then
		AC_MSG_WARN([unable to find PCSC library, compilation will likely fail.])
	fi

	dnl Check for SCardIsValidContext, only in newer PCSC-Lite
	AC_CHECK_FUNCS(SCardIsValidContext)
])

AC_DEFUN(DC_PCSC, [
	DC_PCSC_HEADERS
	DC_PCSC_LIBS
])