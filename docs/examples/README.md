# Examples

This folder contains example configuration for the server profiles feature.

- server.yaml: Place at `/etc/sshuttle/server.yaml` (or `~/.config/sshuttle/server.yaml`).
  - Defines profiles with allowlists for networks and ports, optional DNS nameserver override, and a log path for per-connection JSONL logs.

Note: If a profile's `allow_nets` is empty or omitted, the server defaults to allowing only the locally attached networks discovered from its routing table. This makes the example portable across environments.

