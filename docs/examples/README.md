# Examples

This folder contains example configuration for the server profiles feature.

- server.yaml: Place at `/etc/sshuttle/server.yaml` (or `~/.config/sshuttle/server.yaml`).
  - Defines profiles with allowlists for networks and ports, optional DNS nameserver override, and a log path for per-connection JSONL logs.

Minimal default profile example allows only `10.4.188.128/25`.

