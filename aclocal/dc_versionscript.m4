AC_DEFUN(DC_SETVERSIONSCRIPT, [
	VERSIONSCRIPT="$1"

	SAVE_LDFLAGS="${LDFLAGS}"

	AC_MSG_CHECKING([for how to set version script])

	for addldflags in "-Wl,--version-script -Wl,${VERSIONSCRIPT}"; do
		LDFLAGS="${SAVE_LDFLAGS} ${addldflags}"
		AC_TRY_LINK([], [], [
			AC_MSG_RESULT($addldflags)
		], [
			AC_MSG_RESULT([don't know])

			LDFLAGS="${SAVE_LDFLAGS}"
		])
	done
])
