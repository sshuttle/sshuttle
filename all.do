exec >&2
UI=
[ "$(uname)" = "Darwin" ] && UI=ui-macos/all
redo-ifchange sshuttle.8 $UI

echo
echo "What now?"
[ -z "$UI" ] || echo "- Try the MacOS GUI: open ui-macos/Sshuttle*.app"
echo "- Run sshuttle: ./sshuttle --dns -r HOSTNAME 0/0"
echo "- Read the README: less README.md"
echo "- Read the man page: less sshuttle.md"
