/*
 * This rather pointless program acts like the python interpreter, except
 * it's intended to sit inside a MacOS .app package, so that its argv[0]
 * will point inside the package.
 *
 * NSApplicationMain() looks for Info.plist using the path in argv[0], which
 * goes wrong if your interpreter is /usr/bin/python.
 */
#include <Python.h>

int main(int argc, char **argv)
{
    return Py_Main(argc, argv);
}