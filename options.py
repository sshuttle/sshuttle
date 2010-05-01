import sys, textwrap, getopt, re

class OptDict:
    def __init__(self):
        self._opts = {}

    def __setitem__(self, k, v):
        self._opts[k] = v
        
    def __getitem__(self, k):
        return self._opts[k]

    def __getattr__(self, k):
        return self[k]


class Options:
    def __init__(self, exe, optspec, optfunc=getopt.gnu_getopt):
        self.exe = exe
        self.optspec = optspec
        self.optfunc = optfunc
        self._aliases = {}
        self._shortopts = 'h?'
        self._longopts = ['help']
        self._hasparms = {}
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
        while lines:
            l = lines.pop()
            if l.startswith(' '):
                out.append('\n%s\n' % l.lstrip())
            elif l:
                (flags, extra) = l.split(' ', 1)
                extra = extra.strip()
                if flags.endswith('='):
                    flags = flags[:-1]
                    has_parm = 1
                else:
                    has_parm = 0
                flagl = flags.split(',')
                flagl_nice = []
                for f in flagl:
                    f_nice = re.sub(r'\W', '_', f)
                    self._aliases[f] = flagl[0]
                    self._aliases[f_nice] = flagl[0]
                    self._hasparms[f] = has_parm
                    if len(f) == 1:
                        self._shortopts += f + (has_parm and ':' or '')
                        flagl_nice.append('-' + f)
                    else:
                        assert(not f.startswith('no-')) # supported implicitly
                        self._longopts.append(f + (has_parm and '=' or ''))
                        self._longopts.append('no-' + f)
                        flagl_nice.append('--' + f)
                flags_nice = ', '.join(flagl_nice)
                if has_parm:
                    flags_nice += ' ...'
                prefix = '    %-20s  ' % flags_nice
                argtext = '\n'.join(textwrap.wrap(extra, width=70,
                                                initial_indent=prefix,
                                                subsequent_indent=' '*28))
                out.append(argtext + '\n')
            else:
                out.append('\n')
        return ''.join(out).rstrip() + '\n'
    
    def usage(self):
        sys.stderr.write(self._usagestr)
        sys.exit(97)

    def fatal(self, s):
        sys.stderr.write('error: %s\n' % s)
        return self.usage()
        
    def parse(self, args):
        try:
            (flags,extra) = self.optfunc(args, self._shortopts, self._longopts)
        except getopt.GetoptError, e:
            self.fatal(e)

        opt = OptDict()
        for f in self._aliases.values():
            opt[f] = None
        for (k,v) in flags:
            while k.startswith('-'):
                k = k[1:]
            if k in ['h', '?', 'help']:
                self.usage()
            if k.startswith('no-'):
                k = self._aliases[k[3:]]
                opt[k] = None
            else:
                k = self._aliases[k]
                if not self._hasparms[k]:
                    assert(v == '')
                    opt[k] = (opt._opts.get(k) or 0) + 1
                else:
                    try:
                        vv = int(v)
                        if str(vv) == v:
                            v = vv
                    except ValueError:
                        pass
                    opt[k] = v
        for (f1,f2) in self._aliases.items():
            opt[f1] = opt[f2]
        return (opt,flags,extra)
