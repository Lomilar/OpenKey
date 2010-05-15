#! /bin/bash

TMPFILE="${TMPDIR:-/tmp}/malloc-free-check-$$${RANDOM}${RANDOM}${RANDOM}.tmp"

egrep '(MALLOC|FREE|REALLOC)' "$@" | sed 's@^.*FREE(\(0x[0-9a-f]*\)).*$@free \1@;s@^.*MALLOC() = @malloc @;s@^.*REALLOC(\(0x[0-9a-f]*\)) = @realloc \1 @' > "${TMPFILE}"

cat "${TMPFILE}" | while read op addr newaddr; do
	case "${op}" in
		malloc)
			if [ -z "${alloclist}" ]; then
				alloclist="${addr}"
			else
				alloclist="${alloclist} ${addr}"
			fi
			;;
		free)
			if ! echo " ${alloclist} " | grep " ${addr} " >/dev/null; then
				if [ -z "${alloclist}" ]; then
					alloclist="!${addr}"
				else
					alloclist="${alloclist} !${addr}"
				fi

				continue
			fi
			alloclist="$(echo " ${alloclist} " | sed "s@ ${addr} @ @;s@^  *@@;s@  *\$@@")"
			;;
		realloc)
			alloclist="$(echo " ${alloclist} " | sed "s@ ${addr} @ ${newaddr} @;s@^  *@@;s@  *\$@@")"
			;;
	esac

	echo "${alloclist}"
done | tail -1 | while read leftovers; do
	for leftover in ${leftovers}; do
		case "${leftover}" in
			!*)
				leftover="$(echo "${leftover}" | cut -c 2-)"

				echo "Double freed or never allocated ${leftover}:"
				grep "${leftover}" "$@" | sed 's@^@    @'
				echo ''
				;;
			*)
				echo "Unfreed memory ${leftover}:"
				grep "${leftover}" "$@" | sed 's@^@    @'
				echo ''
				;;
		esac
	done
done

rm -f "${TMPFILE}"
