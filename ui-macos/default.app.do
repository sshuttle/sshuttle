TOP=$PWD
redo-ifchange sources.list
redo-ifchange Info.plist bits/runpython bits/run \
	$(while read name newname; do echo "$name"; done <sources.list)

rm -rf "$1.app"
mkdir "$1.app" "$1.app/Contents"
cd "$1.app/Contents"

cp "$TOP/Info.plist" .

mkdir MacOS
cp "$TOP/bits/runpython" "$TOP/bits/run" MacOS/

mkdir Resources Resources/English.lproj
cp "$TOP/MainMenu.nib" Resources/English.lproj

cd "$TOP"
while read name newname; do
	[ -z "$name" ] && continue
	outname=$1.app/Contents/Resources/$name
	outdir=$(dirname "$outname")
	[ -d "$outdir" ] || mkdir "$outdir"
	cp "${name-newname}" "$outname"
done <sources.list

cd "$1.app"
redo-ifchange $(find . -type f)
