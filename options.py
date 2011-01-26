"""Command-line options parser.
With the help of an options spec string, easily parse command-line options.
"""
import sys, os, textwrap, getopt, re, struct

class OptDict:
    def __init__(self):
        self._opts = {}

    def __setitem__(self, k, v):
        if k.startswith('no-') or k.startswith('no_'):
            k = k[3:]
            v = not v
        self._opts[k] = v

    def __getitem__(self, k):
        if k.startswith('no-') or k.startswith('no_'):
            return not self._opts[k[3:]]
        return self._opts[k]

    def __getattr__(self, k):
        return self[k]


def _default_onabort(msg):
    sys.exit(97)


def _intify(v):
    try:
        vv = int(v or '')
        if str(vv) == v:
            return vv
    except ValueError:
        pass
    return v


def _atoi(v):
    try:
        return int(v or 0)
    except ValueError:
        return 0


def _remove_negative_kv(k, v):
    if k.startswith('no-') or k.startswith('no_'):
        return k[3:], not v
    return k,v

def _remove_negative_k(k):
    return _remove_negative_kv(k, None)[0]


def _tty_width():
    s = struct.pack("HHHH", 0, 0, 0, 0)
    try:
        import fcntl, termios
        s = fcntl.ioctl(sys.stderr.fileno(), termios.TIOCGWINSZ, s)
    except (IOError, ImportError):
        return _atoi(os.environ.get('WIDTH')) or 70
    (ysize,xsize,ypix,xpix) = struct.unpack('HHHH', s)
    return xsize or 70


class Options:
    """Option parser.
    When constructed, two strings are mandatory. The first one is the command
    name showed before error messages. The second one is a string called an
    optspec that specifies the synopsis and option flags and their description.
    For more information about optspecs, consult the bup-options(1) man page.

    Two optional arguments specify an alternative parsing function and an
    alternative behaviour on abort (after having output the usage string).

    By default, the parser function is getopt.gnu_getopt, and the abort
    behaviour is to exit the program.
    """
    def __init__(self, optspec, optfunc=getopt.gnu_getopt,
                 onabort=_default_onabort):
        self.optspec = optspec
        self._onabort = onabort
        self.optfunc = optfunc
        self._aliases = {}
        self._shortopts = 'h?'
        self._longopts = ['help']
        self._hasparms = {}
        self._defaults = {}
        self._usagestr = self._gen_usage()

    def _gen_usage(self):
        out = []
        lines = self.optspec.strip().split('\n')
        lines.reverse()
        first_syn = True
        while lines:
            l = lines.pop()
            if l == '--': break
            out.append('%s: %s\n' % (first_syn and 'usage' or '   or', l))
            first_syn = False
        out.append('\n')
        last_was_option = False
        while lines:
            l = lines.pop()
            if l.startswith(' '):
                out.append('%s%s\n' % (last_was_option and '\n' or '',
                                       l.lstrip()))
                last_was_option = False
            elif l:
                (flags, extra) = l.split(' ', 1)
                extra = extra.strip()
                if flags.endswith('='):
                    flags = flags[:-1]
                    has_parm = 1
                else:
                    has_parm = 0
                g = re.search(r'\[([^\]]*)\]$', extra)
                if g:
                    defval = g.group(1)
                else:
                    defval = None
                flagl = flags.split(',')
                flagl_nice = []
                for _f in flagl:
                    f,dvi = _remove_negative_kv(_f, _intify(defval))
                    self._aliases[f] = _remove_negative_k(flagl[0])
                    self._hasparms[f] = has_parm
                    self._defaults[f] = dvi
                    if len(f) == 1:
                        self._shortopts += f + (has_parm and ':' or '')
                        flagl_nice.append('-' + f)
                    else:
                        f_nice = re.sub(r'\W', '_', f)
                        self._aliases[f_nice] = _remove_negative_k(flagl[0])
                        self._longopts.append(f + (has_parm and '=' or ''))
                        self._longopts.append('no-' + f)
                        flagl_nice.append('--' + _f)
                flags_nice = ', '.join(flagl_nice)
                if has_parm:
                    flags_nice += ' ...'
                prefix = '    %-20s  ' % flags_nice
                argtext = '\n'.join(textwrap.wrap(extra, width=_tty_width(),
                                                initial_indent=prefix,
                                                subsequent_indent=' '*28))
                out.append(argtext + '\n')
                last_was_option = True
            else:
                out.append('\n')
                last_was_option = False
        return ''.join(out).rstrip() + '\n'

    def usage(self, msg=""):
        """Print usage string to stderr and abort."""
        sys.stderr.write(self._usagestr)
        e = self._onabort and self._onabort(msg) or None
        if e:
            raise e

    def fatal(self, s):
        """Print an error message to stderr and abort with usage string."""
        msg = 'error: %s\n' % s
        sys.stderr.write(msg)
        return self.usage(msg)

    def parse(self, args):
        """Parse a list of arguments and return (options, flags, extra).

        In the returned tuple, "options" is an OptDict with known options,
        "flags" is a list of option flags that were used on the command-line,
        and "extra" is a list of positional arguments.
        """
        try:
            (flags,extra) = self.optfunc(args, self._shortopts, self._longopts)
        except getopt.GetoptError, e:
            self.fatal(e)

        opt = OptDict()

        for k,v in self._defaults.iteritems():
            k = self._aliases[k]
            opt[k] = v

        for (k,v) in flags:
            k = k.lstrip('-')
            if k in ('h', '?', 'help'):
                self.usage()
            if k.startswith('no-'):
                k = self._aliases[k[3:]]
                v = 0
            else:
                k = self._aliases[k]
                if not self._hasparms[k]:
                    assert(v == '')
                    v = (opt._opts.get(k) or 0) + 1
                else:
                    v = _intify(v)
            opt[k] = v
        for (f1,f2) in self._aliases.iteritems():
            opt[f1] = opt._opts.get(f2)
        return (opt,flags,extra)
