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

AC_DEFUN(DC_FIND_STRIP_AND_REMOVESYMS, [
	SYMFILE="$1"

	dnl Determine how to strip executables
	AC_CHECK_TOOL(OBJCOPY, objcopy, [false])
	AC_CHECK_TOOL(STRIP, strip, [false])

	if test "x${STRIP}" = "xfalse"; then
		STRIP="${OBJCOPY}"
	fi

	WEAKENSYMS='true'
	REMOVESYMS='true'

	case $host_os in
		darwin*)
			REMOVESYMS="${STRIP} -s ${SYMFILE}"
			;;
		*)
			if test "x${OBJCOPY}" != "xfalse"; then
				WEAKENSYMS="${OBJCOPY} --keep-global-symbols=${SYMFILE}"
				REMOVESYMS="${OBJCOPY} --discard-all"
			elif test "x${STRIP}" != "xfalse"; then
				REMOVESYMS="${STRIP} -x"
			fi
			;;
	esac

	AC_SUBST(WEAKENSYMS)
	AC_SUBST(REMOVESYMS)
])
