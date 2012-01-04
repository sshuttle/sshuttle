exec >&2
IFS="
"
redo-ifchange $2.app
tar -czf $3 $2.app/
