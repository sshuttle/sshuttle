Server-side configuration examples for sshuttle profiles

Overview
- Copy one of these files to a server location sshuttle reads automatically:
  - /etc/sshuttle/server.yaml
  - ~/.config/sshuttle/server.yaml
- JSON is also accepted (it is a valid subset of YAML).
- When a config exists, sshuttle enforces the selected profile and logs per-connection events to the configured log_path.
- When no config exists, sshuttle operates normally (no enforcement) and logs via standard server logging.
- If a client requests --profile but the server has no config, the session fails with a clear error.

How to use
1) Pick an example (YAML or JSON) matching your needs
2) Ensure the log directory exists, for example:
   sudo mkdir -p /var/log/sshuttle && sudo chown $USER /var/log/sshuttle
3) Place the file at /etc/sshuttle/server.yaml (or ~/.config/sshuttle/server.yaml)
4) Start sshuttle; the server will apply the default_profile unless the client passes --profile <name>

Notes
- allow_nets: [] means "auto-discover locally attached IPv4 networks" on the server.
- allow_tcp_ports / allow_udp_ports accept single ports ("22") and ranges ("8000-8010").
- dns_nameserver overrides the DNS server the sshuttle server uses for DNS queries.
- log_path is a server-side file where syslog-like key=value lines are appended.

Files
- server-basic.yaml: Minimal YAML with auto-discovered networks and common ports
- server-dns-override.yaml: Adds a DNS override per profile
- server-multi-profiles.yaml: Two profiles (default and contractor) with different scopes
- server.json: JSON variant of a basic configuration

