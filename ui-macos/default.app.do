TOP=$PWD
redo-ifchange sources.list
redo-ifchange Info.plist bits/runpython \
	$(while read name newname; do echo "$name"; done <sources.list)

rm -rf "$1.app"
mkdir "$1.app" "$1.app/Contents"
cd "$1.app/Contents"

cp "$TOP/Info.plist" .

mkdir MacOS
cp "$TOP/bits/runpython" MacOS/Sshuttle

mkdir Resources

cd "$TOP"
while read name newname; do
	[ -z "$name" ] && continue
	: "${newname:=$name}"
	outname=$1.app/Contents/Resources/$newname
	outdir=$(dirname "$outname")
	[ -d "$outdir" ] || mkdir "$outdir"
	cp "${name-$newname}" "$outname"
done <sources.list

cd "$1.app"
redo-ifchange $(find . -type f)
