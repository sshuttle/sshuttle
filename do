#!/bin/sh
#
# A minimal alternative to djb redo that doesn't support incremental builds.
# For the full version, visit http://github.com/apenwarr/redo
#
# The author disclaims copyright to this source file and hereby places it in
# the public domain. (2010 12 14)
#

# By default, no output coloring.
GREEN=""
BOLD=""
PLAIN=""

if [ -n "$TERM" -a "$TERM" != "dumb" ] && tty <&2 >/dev/null 2>&1; then
	GREEN="$(printf '\033[32m')"
	BOLD="$(printf '\033[1m')"
	PLAIN="$(printf '\033[m')"
fi

_dirsplit()
{
	base=${1##*/}
	dir=${1%$base}
}

_dirsplit "$0"
export REDO=$(cd "${dir:-.}" && echo "$PWD/$base")

DO_TOP=
if [ -z "$DO_BUILT" ]; then
	DO_TOP=1
	[ -n "$*" ] || set all  # only toplevel redo has a default target
	export DO_BUILT=$PWD/.do_built
	: >>"$DO_BUILT"
	echo "Removing previously built files..." >&2
	sort -u "$DO_BUILT" | tee "$DO_BUILT.new" |
	while read f; do printf "%s\0%s.did\0" "$f" "$f"; done |
	xargs -0 rm -f 2>/dev/null
	mv "$DO_BUILT.new" "$DO_BUILT"
	DO_PATH=$DO_BUILT.dir
	export PATH=$DO_PATH:$PATH
	rm -rf "$DO_PATH"
	mkdir "$DO_PATH"
	for d in redo redo-ifchange; do
		ln -s "$REDO" "$DO_PATH/$d";
	done
	[ -e /bin/true ] && TRUE=/bin/true || TRUE=/usr/bin/true
	for d in redo-ifcreate redo-stamp redo-always; do 
		ln -s $TRUE "$DO_PATH/$d";
	done
fi


_find_dofile_pwd()
{
	DOFILE=default.$1.do
	while :; do
		DOFILE=default.${DOFILE#default.*.}
		[ -e "$DOFILE" -o "$DOFILE" = default.do ] && break
	done
	EXT=${DOFILE#default}
	EXT=${EXT%.do}
	BASE=${1%$EXT}
}


_find_dofile()
{
	PREFIX=
	while :; do
		_find_dofile_pwd "$1"
		[ -e "$DOFILE" ] && break
		[ "$PWD" = "/" ] && break
		TARGET=${PWD##*/}/$TARGET
		PREFIX=${PWD##*/}/$PREFIX
		cd ..
	done
	BASE=$PREFIX$BASE
}


_run_dofile()
{
	export DO_DEPTH="$DO_DEPTH  "
	export REDO_TARGET=$PWD/$TARGET
	set -e
	read line1 <"$PWD/$DOFILE"
	cmd=${line1#"#!/"}
	if [ "$cmd" != "$line1" ]; then
		/$cmd "$PWD/$DOFILE" "$@" >"$TARGET.tmp2"
	else
		. "$PWD/$DOFILE" >"$TARGET.tmp2"
	fi
}


_do()
{
	DIR=$1
	TARGET=$2
	if [ ! -e "$TARGET" ] || [ -e "$TARGET/." -a ! -e "$TARGET.did" ]; then
		printf '%sdo  %s%s%s%s\n' \
			"$GREEN" "$DO_DEPTH" "$BOLD" "$DIR$TARGET" "$PLAIN" >&2
		echo "$PWD/$TARGET" >>"$DO_BUILT"
		DOFILE=$TARGET.do
		BASE=$TARGET
		EXT=
		[ -e "$TARGET.do" ] || _find_dofile "$TARGET"
		if [ ! -e "$DOFILE" ]; then
			echo "do: $TARGET: no .do file" >&2
			return 1
		fi
		[ ! -e "$DO_BUILD" ] || : >>"$TARGET.did"
		( _run_dofile "$BASE" "$EXT" "$TARGET.tmp" )
		RV=$?
		if [ $RV != 0 ]; then
			printf "do: %s%s\n" "$DO_DEPTH" \
				"$DIR$TARGET: got exit code $RV" >&2
			rm -f "$TARGET.tmp" "$TARGET.tmp2"
			return $RV
		fi
		mv "$TARGET.tmp" "$TARGET" 2>/dev/null ||
		! test -s "$TARGET.tmp2" ||
		mv "$TARGET.tmp2" "$TARGET" 2>/dev/null
		rm -f "$TARGET.tmp2"
	else
		echo "do  $DO_DEPTH$TARGET exists." >&2
	fi
}


redo()
{
	for i in "$@"; do
		_dirsplit "$i"
		( cd "$dir" && _do "$dir" "$base" ) || return 1
	done
}


set -e
redo "$@"

if [ -n "$DO_TOP" ]; then
	echo "Removing stamp files..." >&2
	[ ! -e "$DO_BUILT" ] ||
	while read f; do printf "%s.did\0" "$f"; done <"$DO_BUILT" |
	xargs -0 rm -f 2>/dev/null
fi
