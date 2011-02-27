UI=
[ "$(uname)" = "Darwin" ] && UI=ui-macos/all
redo-ifchange sshuttle.8 $UI

