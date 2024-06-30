import sys
import zlib
import types
import platform

stdin = stdin  # type: typing.BinaryIO # noqa: F821 must be a previously defined global
verbosity = verbosity  # type: int # noqa: F821 must be a previously defined global
if verbosity > 0:
    sys.stderr.write(' s: Running server on remote host with %s (version %s)\n'
                     % (sys.executable, platform.python_version()))

z = zlib.decompressobj()

while 1:
    name = stdin.readline().strip()
    if name:
        # python2 compat: in python2 stdin.readline().strip() -> str
        #                 in python3 stdin.readline().strip() -> bytes
        # (see #481)
        if sys.version_info >= (3, 0):
            name = name.decode("ASCII")
        nbytes = int(stdin.readline())
        if verbosity >= 2:
            sys.stderr.write(' s: assembling %r (%d bytes)\n'
                             % (name, nbytes))
        content = z.decompress(stdin.read(nbytes))

        module = types.ModuleType(name)
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

main(options.latency_control, options.latency_buffer_size,
     options.auto_hosts, options.to_nameserver,
     options.auto_nets)
