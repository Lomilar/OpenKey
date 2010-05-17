AC_DEFUN(DC_SETVERSIONSCRIPT, [
	VERSIONSCRIPT="$1"

	SAVE_LDFLAGS="${LDFLAGS}"

	AC_MSG_CHECKING([for how to set version script])

	for tryaddldflags in "-Wl,--version-script -Wl,${VERSIONSCRIPT}"; do
		LDFLAGS="${SAVE_LDFLAGS} ${tryaddldflags}"
		AC_TRY_LINK([], [], [
			addldflags="${tryaddldflags}"

			break
		])
	done

	if test -n "${addldflags}"; then
		LDFLAGS="${SAVE_LDFLAGS} ${addldflags}"
		AC_MSG_RESULT($addldflags)
	else
		LDFLAGS="${SAVE_LDFLAGS}"
		AC_MSG_RESULT([don't know])
	fi
])
