exec >&2
redo-ifchange runpython.c
ARCHES=""
for d in /usr/libexec/gcc/darwin/*; do
    ARCHES="$ARCHES -arch $(basename $d)"
done
gcc $ARCHES \
	-Wall -o $3 runpython.c \
	-I/usr/include/python2.5 \
	-lpython2.5
