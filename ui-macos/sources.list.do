redo-always
exec >$3
cat <<-EOF
	app.icns
	MainMenu.nib English.lproj/MainMenu.nib
	UserDefaults.plist
	chicken-tiny.png
	chicken-tiny-bw.png
	chicken-tiny-err.png
EOF
for d in *.py sshuttle/*.py sshuttle/sshuttle sshuttle/compat/*.py; do
	echo $d
done
redo-stamp <$3
