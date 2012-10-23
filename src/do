#!/bin/sh
#
# A minimal alternative to djb redo that doesn't support incremental builds.
# For the full version, visit http://github.com/apenwarr/redo
#
# The author disclaims copyright to this source file and hereby places it in
# the public domain. (2010 12 14)
#

# By default, no output coloring.
green=""
bold=""
plain=""

if [ -n "$TERM" -a "$TERM" != "dumb" ] && tty <&2 >/dev/null 2>&1; then
	green="$(printf '\033[32m')"
	bold="$(printf '\033[1m')"
	plain="$(printf '\033[m')"
fi

_dirsplit()
{
	base=${1##*/}
	dir=${1%$base}
}

dirname()
(
	_dirsplit "$1"
	dir=${dir%/}
	echo "${dir:-.}"
)

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
	dofile=default.$1.do
	while :; do
		dofile=default.${dofile#default.*.}
		[ -e "$dofile" -o "$dofile" = default.do ] && break
	done
	ext=${dofile#default}
	ext=${ext%.do}
	base=${1%$ext}
}


_find_dofile()
{
	local prefix=
	while :; do
		_find_dofile_pwd "$1"
		[ -e "$dofile" ] && break
		[ "$PWD" = "/" ] && break
		target=${PWD##*/}/$target
		tmp=${PWD##*/}/$tmp
		prefix=${PWD##*/}/$prefix
		cd ..
	done
	base=$prefix$base
}


_run_dofile()
{
	export DO_DEPTH="$DO_DEPTH  "
	export REDO_TARGET=$PWD/$target
	local line1
	set -e
	read line1 <"$PWD/$dofile"
	cmd=${line1#"#!/"}
	if [ "$cmd" != "$line1" ]; then
		/$cmd "$PWD/$dofile" "$@" >"$tmp.tmp2"
	else
		:; . "$PWD/$dofile" >"$tmp.tmp2"
	fi
}


_do()
{
	local dir=$1 target=$2 tmp=$3
	if [ ! -e "$target" ] || [ -d "$target" -a ! -e "$target.did" ]; then
		printf '%sdo  %s%s%s%s\n' \
			"$green" "$DO_DEPTH" "$bold" "$dir$target" "$plain" >&2
		echo "$PWD/$target" >>"$DO_BUILT"
		dofile=$target.do
		base=$target
		ext=
		[ -e "$target.do" ] || _find_dofile "$target"
		if [ ! -e "$dofile" ]; then
			echo "do: $target: no .do file" >&2
			return 1
		fi
		[ ! -e "$DO_BUILT" ] || [ ! -d "$(dirname "$target")" ] ||
		: >>"$target.did"
		( _run_dofile "$base" "$ext" "$tmp.tmp" )
		rv=$?
		if [ $rv != 0 ]; then
			printf "do: %s%s\n" "$DO_DEPTH" \
				"$dir$target: got exit code $rv" >&2
			rm -f "$tmp.tmp" "$tmp.tmp2"
			return $rv
		fi
		mv "$tmp.tmp" "$target" 2>/dev/null ||
		! test -s "$tmp.tmp2" ||
		mv "$tmp.tmp2" "$target" 2>/dev/null
		rm -f "$tmp.tmp2"
	else
		echo "do  $DO_DEPTH$target exists." >&2
	fi
}


# Make corrections for directories that don't actually exist yet.
_dir_shovel()
{
	local dir base
	xdir=$1 xbase=$2 xbasetmp=$2
	while [ ! -d "$xdir" -a -n "$xdir" ]; do
		_dirsplit "${xdir%/}"
		xbasetmp=${base}__$xbase
		xdir=$dir xbase=$base/$xbase
		echo "xbasetmp='$xbasetmp'" >&2
	done
}


redo()
{
	for i in "$@"; do
		_dirsplit "$i"
		_dir_shovel "$dir" "$base"
		dir=$xdir base=$xbase basetmp=$xbasetmp
		( cd "$dir" && _do "$dir" "$base" "$basetmp" ) || return 1
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
