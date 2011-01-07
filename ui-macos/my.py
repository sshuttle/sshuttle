import sys, os
from AppKit import *
import PyObjCTools.AppHelper


def bundle_path(name, typ):
    if typ:
        return NSBundle.mainBundle().pathForResource_ofType_(name, typ)
    else:
        return os.path.join(NSBundle.mainBundle().resourcePath(), name)


# Load an NSData using a python string
def Data(s):
    return NSData.alloc().initWithBytes_length_(s, len(s))


# Load a property list from a file in the application bundle.
def PList(name):
    path = bundle_path(name, 'plist')
    return NSDictionary.dictionaryWithContentsOfFile_(path)


# Load an NSImage from a file in the application bundle.
def Image(name, ext):
    bytes = open(bundle_path(name, ext)).read()
    img = NSImage.alloc().initWithData_(Data(bytes))
    return img


# Return the NSUserDefaults shared object.
def Defaults():
    return NSUserDefaults.standardUserDefaults()


# Usage:
#   f = DelayedCallback(func, args...)
# later:
#   f()
#
# When you call f(), it will schedule a call to func() next time the
# ObjC event loop iterates.  Multiple calls to f() in a single iteration
# will only result in one call to func().
#
def DelayedCallback(func, *args, **kwargs):
    flag = [0]
    def _go():
        if flag[0]:
            print 'running %r (flag=%r)' % (func, flag)
            flag[0] = 0
            func(*args, **kwargs)
    def call():
        flag[0] += 1
        PyObjCTools.AppHelper.callAfter(_go)
    return call


def atoi(s):
    try:
        return int(s)
    except ValueError:
        return 0
