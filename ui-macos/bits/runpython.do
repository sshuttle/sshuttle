exec >&2
redo-ifchange runpython.c
gcc -Wall -o $3 runpython.c \
	-I/usr/include/python2.5 \
	-lpython2.5
