#!/bin/sh

wait_for_tor_bootstrap() {
    echo "Waiting for Tor to bootstrap..."
    while true; do
        if echo -e "AUTHENTICATE \"\"\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n" | nc 127.0.0.1 9051 2>/dev/null | grep -q '100% (done)'; then
            echo "Tor selesai bootstrap."
            break;
        fi
        sleep 5
    done
}

/usr/bin/tor &

wait_for_tor_bootstrap

exec /usr/bin/nanoproxy