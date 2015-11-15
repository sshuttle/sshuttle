TOP=$PWD
redo-ifchange sources.list
redo-ifchange Info.plist bits/runpython \
	$(while read name newname; do echo "$name"; done <sources.list)

rm -rf "$2.app"
mkdir "$2.app" "$2.app/Contents"
cd "$2.app/Contents"

cp "$TOP/Info.plist" .

mkdir MacOS
cp "$TOP/bits/runpython" MacOS/Sshuttle

mkdir Resources

cd "$TOP"
while read name newname; do
	[ -z "$name" ] && continue
	: "${newname:=$name}"
	outname=$2.app/Contents/Resources/$newname
	outdir=$(dirname "$outname")
	[ -d "$outdir" ] || mkdir "$outdir"
	cp "${name-$newname}" "$outname"
done <sources.list

cd "$2.app"
redo-ifchange $(find . -type f)
