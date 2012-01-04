exec >&2
IFS="
"
redo-ifchange $2.app
zip -q -r $3 $2.app/
