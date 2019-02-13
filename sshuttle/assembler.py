import sys
import zlib
import imp

verbosity = verbosity  # noqa: F821 must be a previously defined global
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
        exec(code, module.__dict__)  # nosec
        sys.modules[name] = module
    else:
        break

sys.stderr.flush()
sys.stdout.flush()

# import can only happen once the code has been transferred to
# the server. 'noqa: E402' excludes these lines from QA checks.
import sshuttle.helpers  # noqa: E402
sshuttle.helpers.verbose = verbosity

import sshuttle.cmdline_options as options  # noqa: E402
from sshuttle.server import main  # noqa: E402
main(options.latency_control, options.auto_hosts, options.to_nameserver,
     options.auto_nets)
