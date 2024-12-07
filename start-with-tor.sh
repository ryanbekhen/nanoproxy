#!/bin/sh

wait_for_tor_bootstrap() {
    echo "Waiting for Tor to bootstrap..."
    while true; do
        BOOTSTRAP_STATUS=$(printf 'GETINFO status/bootstrap-phase\nQUIT\n' | nc 127.0.0.1 9051 2>/dev/null | grep '100% (done)')
        if [ -n "$BOOTSTRAP_STATUS" ]; then
            echo "Tor has bootstrapped 100%"
            break
        fi
        sleep 1
    done
}

/usr/bin/tor &

wait_for_tor_bootstrap

exec /usr/bin/nanoproxy