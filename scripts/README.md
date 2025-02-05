# Container based test bed for sshuttle

```bash
test-bed up -d # start containers

exec-sshuttle <node-id> [--copy-id] [--server-py=2.7|3.10] [--client-py=2.7|3.10] [--sshuttle-bin=/path/to/sshuttle] [sshuttle-args...]
    # --copy-id  -> optionally do ssh-copy-id to make it passwordless for future runs
    # --sshuttle-bin -> use another sshuttle binary instead of one from dev setup
    # --server-py  -> Python version to use in server. (manged by pyenv)
    # --client-py -> Python version to use in client (manged by pyenv)

exec-sshuttle node-1 # start sshuttle to connect to node-1

exec-tool curl node-1  # curl to nginx instance running on node1 via IP that is only reachable via sshuttle
exec-tool iperf3 node-1 # measure throughput to node-1

run-benchmark node-1 --client-py=3.10

```

<https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration#configuring-the-default-shell-for-openssh-in-windows>
