/*
 * This rather pointless program acts like the python interpreter, except
 * it's intended to sit inside a MacOS .app package, so that its argv[0]
 * will point inside the package.
 *
 * NSApplicationMain() looks for Info.plist using the path in argv[0], which
 * goes wrong if your interpreter is /usr/bin/python.
 */
#include <Python.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char *path = strdup(argv[0]), *cptr;
    char *args[] = {argv[0], "../Resources/main.py", NULL};
    cptr = strrchr(path, '/');
    if (cptr)
	*cptr = 0;
    chdir(path);
    free(path);
    return Py_Main(2, args);
}
