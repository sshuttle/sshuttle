# Container based test bed for sshuttle

```bash
test-bed up -d # start containers

exec-sshuttle <node> [--copy-id] [--sshuttle-bin=/path/to/sshuttle] [sshuttle-args...]

exec-sshuttle node-1 # start sshuttle to connect to node-1

exec-tool curl node-1  # curl to nginx instance running on node1 via IP that is only reachable via sshuttle
exec-tool iperf3 node-1 # measure throughput to node-1

```
