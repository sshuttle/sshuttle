import sys
import zlib
import imp

z = zlib.decompressobj()
while 1:
    name = sys.stdin.readline().strip()
    if name:
        name = name.decode("ASCII")

        nbytes = int(sys.stdin.readline())
        if verbosity >= 2:
            sys.stderr.write('server: assembling %r (%d bytes)\n'
                             % (name, nbytes))
        content = z.decompress(sys.stdin.read(nbytes))

        module = imp.new_module(name)
        parents = name.rsplit(".", 1)
        if len(parents) == 2:
            parent, parent_name = parents
            setattr(sys.modules[parent], parent_name, module)

        code = compile(content, name, "exec")
        exec(code, module.__dict__)
        sys.modules[name] = module
    else:
        break

sys.stderr.flush()
sys.stdout.flush()

import sshuttle.helpers
sshuttle.helpers.verbose = verbosity

import sshuttle.cmdline_options as options
from sshuttle.server import main
main(options.latency_control, options.auto_hosts)
