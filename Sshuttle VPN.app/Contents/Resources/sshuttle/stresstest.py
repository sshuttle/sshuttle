#!/usr/bin/env python
import sys, os, socket, select, struct, time

listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen(500)

servers = []
clients = []
remain = {}

NUMCLIENTS = 50
count = 0


while 1:
    if len(clients) < NUMCLIENTS:
        c = socket.socket()
        c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        c.bind(('0.0.0.0', 0))
        c.connect(listener.getsockname())
        count += 1
        if count >= 16384:
            count = 1
        print 'cli CREATING %d' % count
        b = struct.pack('I', count) + 'x'*count
        remain[c] = count
        print 'cli  >> %r' % len(b)
        c.send(b)
        c.shutdown(socket.SHUT_WR)
        clients.append(c)
        r = [listener]
        time.sleep(0.1)
    else:
        r = [listener]+servers+clients
    print 'select(%d)' % len(r)
    r,w,x = select.select(r, [], [], 5)
    assert(r)
    for i in r:
        if i == listener:
            s,addr = listener.accept()
            servers.append(s)
        elif i in servers:
            b = i.recv(4096)
            print 'srv <<  %r' % len(b)
            if not i in remain:
                assert(len(b) >= 4)
                want = struct.unpack('I', b[:4])[0]
                b = b[4:]
                #i.send('y'*want)
            else:
                want = remain[i]
            if want < len(b):
                print 'weird wanted %d bytes, got %d: %r' % (want, len(b), b)
                assert(want >= len(b))
            want -= len(b)
            remain[i] = want
            if not b:  # EOF
                if want:
                    print 'weird: eof but wanted %d more' % want
                    assert(want == 0)
                i.close()
                servers.remove(i)
                del remain[i]
            else:
                print 'srv  >> %r' % len(b)
                i.send('y'*len(b))
                if not want:
                    i.shutdown(socket.SHUT_WR)
        elif i in clients:
            b = i.recv(4096)
            print 'cli <<  %r' % len(b)
            want = remain[i]
            if want < len(b):
                print 'weird wanted %d bytes, got %d: %r' % (want, len(b), b)
                assert(want >= len(b))
            want -= len(b)
            remain[i] = want
            if not b:  # EOF
                if want:
                    print 'weird: eof but wanted %d more' % want
                    assert(want == 0)
                i.close()
                clients.remove(i)
                del remain[i]
listener.accept()
