exec >&2
redo-ifchange runpython.c
gcc -arch ppc -arch i386 -arch x86_64 \
	-Wall -o $3 runpython.c \
	-I/usr/include/python2.5 \
	-lpython2.5
