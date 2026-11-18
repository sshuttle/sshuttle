import io

from sshuttle import client


def test_hosts_are_sent_as_one_batch():
    fw = client.FirewallClient.__new__(client.FirewallClient)
    fw.pfile = io.BytesIO()
    fw.sethostips(b'host-a,1.2.3.4\nwithout-comma\n,1.2.3.9\n'
                  b'no-ip,\nhost-b,1.2.3.5\n')
    assert fw.pfile.getvalue() == (b'HOST host-a,1.2.3.4\n'
                                   b'HOST host-b,1.2.3.5\n'
                                   b'HOSTS_END\n')

    fw.pfile = io.BytesIO()
    fw.sethostips(b'without-comma\n')
    assert fw.pfile.getvalue() == b''
