exec >&2
IFS="
"
redo-ifchange $1.app
zip -q -r $3 $1.app/
