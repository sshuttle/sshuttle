#!/usr/bin/with-contenv bash
# shellcheck shell=bash

set -e

function with_set_x() {
    set -x
    "$@"
    {
        ec=$?
        set +x
        return $ec
    } 2>/dev/null
}


function log() {
    echo "$*" >&2
}

log ">>> Setting up $(hostname) | id: $(id)\nIP:\n$(ip a)\nRoutes:\n$(ip r)\npyenv:\n$(pyenv versions)"

echo "
AcceptEnv PYENV_VERSION
" >> /etc/ssh/sshd_config

iface="$(ip route | awk '/default/ { print $5 }')"
default_gw="$(ip route | awk '/default/ { print $3 }')"
for addr in ${ADD_IP_ADDRESSES//,/ }; do
    log ">>> Adding $addr to interface $iface"
    net_addr=$(ipcalc -n "$addr" | awk -F= '{print $2}')
    with_set_x ip addr add "$addr" dev "$iface"
    with_set_x ip route add "$net_addr" via "$default_gw" dev "$iface" # so that sshuttle -N can discover routes
done

log ">>> Starting iperf3 server"
iperf3 --server --port 5001 &

mkdir -p /www
echo "<h5>Hello from $(hostname)</h5>
<pre>
<u>ip address</u>
$(ip address)
<u>ip route</u>
$(ip route)
</pre>" >/www/index.html
echo " 
daemon off;
worker_processes 1;
error_log /dev/stdout info;
events {
    worker_connections 1024;
}
http {
    include /etc/nginx/mime.types;
    server {
        access_log /dev/stdout;
        listen 8080 default_server;
        listen [::]:8080 default_server;
        root /www;
    }
}" >/etc/nginx/nginx.conf

log ">>> Starting nginx"
nginx &
