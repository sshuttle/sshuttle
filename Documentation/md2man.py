#!/usr/bin/env python
import sys, os, markdown, re
from BeautifulSoup import BeautifulSoup

def _split_lines(s):
    return re.findall(r'([^\n]*\n?)', s)
    

class Writer:
    def __init__(self):
        self.started = False
        self.indent = 0
        self.last_wrote = '\n'

    def _write(self, s):
        if s:
            self.last_wrote = s
            sys.stdout.write(s)

    def writeln(self, s):
        if s:
            self.linebreak()
            self._write('%s\n' % s)

    def write(self, s):
        if s:
            self.para()
            for line in _split_lines(s):
                if line.startswith('.'):
                    self._write('\\&' + line)
                else:
                    self._write(line)

    def linebreak(self):
        if not self.last_wrote.endswith('\n'):
            self._write('\n')

    def para(self, bullet=None):
        if not self.started:
            if not bullet:
                bullet = ' '
            if not self.indent:
                self.writeln(_macro('.PP'))
            else:
                assert(self.indent >= 2)
                prefix = ' '*(self.indent-2) + bullet + ' '
                self.writeln('.IP "%s" %d' % (prefix, self.indent))
            self.started = True

    def end_para(self):
        self.linebreak()
        self.started = False

    def start_bullet(self):
        self.indent += 3
        self.para(bullet='\\[bu]')

    def end_bullet(self):
        self.indent -= 3
        self.end_para()

w = Writer()


def _macro(name, *args):
    if not name.startswith('.'):
        raise ValueError('macro names must start with "."')
    fixargs = []
    for i in args:
        i = str(i)
        i = i.replace('\\', '')
        i = i.replace('"', "'")
        if (' ' in i) or not i:
            i = '"%s"' % i
        fixargs.append(i)
    return ' '.join([name] + list(fixargs))


def macro(name, *args):
    w.writeln(_macro(name, *args))


def _force_string(owner, tag):
    if tag.string:
        return tag.string
    else:
        out = ''
        for i in tag:
            if not (i.string or i.name in ['a', 'br']):
                raise ValueError('"%s" tags must contain only strings: '
                                 'got %r: %r' % (owner.name, tag.name, tag))
            out += _force_string(owner, i)
        return out


def _clean(s):
    s = s.replace('\\', '\\\\')
    return s


def _bitlist(tag):
    if getattr(tag, 'contents', None) == None:
        for i in _split_lines(str(tag)):
            yield None,_clean(i)
    else:
        for e in tag:
            name = getattr(e, 'name', None)
            if name in ['a', 'br']:
                name = None  # just treat as simple text
            s = _force_string(tag, e)
            if name:
                yield name,_clean(s)
            else:
                for i in _split_lines(s):
                    yield None,_clean(i)


def _bitlist_simple(tag):
    for typ,text in _bitlist(tag):
        if typ and not typ in ['em', 'strong', 'code']:
            raise ValueError('unexpected tag %r inside %r' % (typ, tag.name))
        yield text


def _text(bitlist):
    out = ''
    for typ,text in bitlist:
        if not typ:
            out += text
        elif typ == 'em':
            out += '\\fI%s\\fR' % text
        elif typ in ['strong', 'code']:
            out += '\\fB%s\\fR' % text
        else:
            raise ValueError('unexpected tag %r inside %r' % (typ, tag.name))
    out = out.strip()
    out = re.sub(re.compile(r'^\s+', re.M), '', out)
    return out


def text(tag):
    w.write(_text(_bitlist(tag)))


# This is needed because .BI (and .BR, .RB, etc) are weird little state
# machines that alternate between two fonts.  So if someone says something
# like foo<b>chicken</b><b>wicken</b>dicken we have to convert that to
#   .BI foo chickenwicken dicken
def _boldline(l):
    out = ['']
    last_bold = False
    for typ,text in l:
        nonzero = not not typ
        if nonzero != last_bold:
            last_bold = not last_bold
            out.append('')
        out[-1] += re.sub(r'\s+', ' ', text)
    macro('.BI', *out)


def do_definition(tag):
    w.end_para()
    macro('.TP')
    w.started = True
    split = 0
    pre = []
    post = []
    for typ,text in _bitlist(tag):
        if split:
            post.append((typ,text))
        elif text.lstrip().startswith(': '):
            split = 1
            post.append((typ,text.lstrip()[2:].lstrip()))
        else:
            pre.append((typ,text))
    _boldline(pre)
    w.write(_text(post))


def do_list(tag):
    for i in tag:
        name = getattr(i, 'name', '').lower()
        if not name and not str(i).strip():
            pass
        elif name != 'li':
            raise ValueError('only <li> is allowed inside <ul>: got %r' % i)
        else:
            w.start_bullet()
            for xi in i:
                do(xi)
                w.end_para()
            w.end_bullet()


def do(tag):
    name = getattr(tag, 'name', '').lower()
    if not name:
        text(tag)
    elif name == 'h1':
        macro('.SH', _force_string(tag, tag).upper())
        w.started = True
    elif name == 'h2':
        macro('.SS', _force_string(tag, tag))
        w.started = True
    elif name.startswith('h') and len(name)==2:
        raise ValueError('%r invalid - man page headers must be h1 or h2'
                         % name)
    elif name == 'pre':
        t = _force_string(tag.code, tag.code)
        if t.strip():
            macro('.RS', '+4n')
            macro('.nf')
            w.write(_clean(t).rstrip())
            macro('.fi')
            macro('.RE')
            w.end_para()
    elif name == 'p' or name == 'br':
        g = re.match(re.compile(r'([^\n]*)\n +: +(.*)', re.S), str(tag))
        if g:
            # it's a definition list (which some versions of python-markdown
            # don't support, including the one in Debian-lenny, so we can't
            # enable that markdown extension).  Fake it up.
            do_definition(tag)
        else:
            text(tag)
            w.end_para()
    elif name == 'ul':
        do_list(tag)
    else:
        raise ValueError('non-man-compatible html tag %r' % name)
        
    
PROD='Untitled'
VENDOR='Vendor Name'
SECTION='9'
GROUPNAME='User Commands'
DATE=''
AUTHOR=''

lines = []
if len(sys.argv) > 1:
    for n in sys.argv[1:]:
        lines += open(n).read().decode('utf8').split('\n')
else:
    lines += sys.stdin.read().decode('utf8').split('\n')

# parse pandoc-style document headers (not part of markdown)
g = re.match(r'^%\s+(.*?)\((.*?)\)\s+(.*)$', lines[0])
if g:
    PROD = g.group(1)
    SECTION = g.group(2)
    VENDOR = g.group(3)
    lines.pop(0)
g = re.match(r'^%\s+(.*?)$', lines[0])
if g:
    AUTHOR = g.group(1)
    lines.pop(0)
g = re.match(r'^%\s+(.*?)$', lines[0])
if g:
    DATE = g.group(1)
    lines.pop(0)
g = re.match(r'^%\s+(.*?)$', lines[0])
if g:
    GROUPNAME = g.group(1)
    lines.pop(0)

inp = '\n'.join(lines)
if AUTHOR:
    inp += ('\n# AUTHOR\n\n%s\n' % AUTHOR).replace('<', '\\<')

html = markdown.markdown(inp)
soup = BeautifulSoup(html, convertEntities=BeautifulSoup.HTML_ENTITIES)

macro('.TH', PROD.upper(), SECTION, DATE, VENDOR, GROUPNAME)
macro('.ad', 'l')  # left justified
macro('.nh')  # disable hyphenation
for e in soup:
    do(e)
