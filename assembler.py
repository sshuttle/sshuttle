import sys, zlib

z = zlib.decompressobj()
mainmod = sys.modules[__name__]
while 1:
    name = sys.stdin.readline().strip()
    if name:
        nbytes = int(sys.stdin.readline())
        if verbosity >= 2:
            sys.stderr.write('server: assembling %r (%d bytes)\n'
                             % (name, nbytes))
        content = z.decompress(sys.stdin.read(nbytes))
        exec compile(content, name, "exec")

        # FIXME: this crushes everything into a single module namespace,
        # then makes each of the module names point at this one. Gross.
        assert(name.endswith('.py'))
        modname = name[:-3]
        mainmod.__dict__[modname] = mainmod
    else:
        break

verbose = verbosity
sys.stderr.flush()
sys.stdout.flush()
main()
