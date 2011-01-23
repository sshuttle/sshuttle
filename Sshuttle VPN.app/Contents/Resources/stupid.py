import os

pid = os.fork()
if pid == 0:
    # child
    try:
        os.setsid()
        #os.execvp('sudo', ['sudo', 'SSH_ASKPASS=%s' % os.path.abspath('askpass.py'), 'ssh', 'afterlife', 'ls'])
        os.execvp('ssh', ['ssh', 'afterlife', 'ls'])
    finally:
        os._exit(44)
else:
    # parent
    os.wait()
