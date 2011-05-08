exec >&2
redo-ifchange runpython.c
ARCHES=""
printf "Platforms: "
for d in /usr/libexec/gcc/darwin/*; do
    PLAT=$(basename "$d")
    ARCHES="$ARCHES -arch $PLAT"
    printf "$PLAT "
done
printf "\n"
gcc $ARCHES \
	-Wall -o $3 runpython.c \
	-I/usr/include/python2.5 \
	-lpython2.5
