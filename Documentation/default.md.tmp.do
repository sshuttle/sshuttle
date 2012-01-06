redo-ifchange ../version/vars $2.md
. ../version/vars
sed -e "s/%VERSION%/$TAG/" -e "s/%DATE%/$DATE/" $2.md
