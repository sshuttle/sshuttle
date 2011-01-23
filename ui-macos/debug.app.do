redo-ifchange bits/runpython MainMenu.nib
rm -rf debug.app
mkdir debug.app debug.app/Contents
cd debug.app/Contents
ln -s ../.. Resources
ln -s ../.. English.lproj
ln -s ../../Info.plist .
ln -s ../../app.icns .

mkdir MacOS
cd MacOS
ln -s ../../../bits/runpython Sshuttle

cd ../../..
redo-ifchange $(find debug.app -type f)
