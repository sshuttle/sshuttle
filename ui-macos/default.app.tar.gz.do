exec >&2
IFS="
"
redo-ifchange $1.app
tar -czf $3 $1.app/
