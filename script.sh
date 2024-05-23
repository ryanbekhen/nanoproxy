#!/bin/bash

set -e

function start_nanoproxy_if_need() {
  if pgrep -x "nanoproxy" >/dev/null; then
    return
  fi

  # start the proxy
  nohup nanoproxy >/dev/null 2>&1 &
}

function register_if_need() {
  if [ -f /var/lib/cloudflare-warp/reg.json ]; then
    return
  fi

  # if /var/lib/cloudflare-warp/reg.json not exists, register the warp client
  warp-cli register && echo "Warp client registered!"
  # if a license key is provided, register the license
  if [ -n "$WARP_LICENSE_KEY" ]; then
    echo "License key found, registering license..."
    warp-cli set-license "$WARP_LICENSE_KEY" && echo "Warp license registered!"
  fi
}

function wait_for_warp_ready() {

  echo -e "\n\n------------------------------"
  echo "Waiting for WARP service..."
  echo -e "------------------------------\n\n"

  sleep 1

  while true; do

    if ! warp-cli status >/dev/null 2>&1; then

      sleep 1
      continue

    fi

    break

  done

  echo -e "\n\n------------------------------"
  echo "WARP service started!"
  echo -e "------------------------------\n\n"
}

function run_after_warp_ready() {
  wait_for_warp_ready
  register_if_need
  warp-cli set-mode warp
  warp-cli connect
}

#########################################################

start_nanoproxy_if_need
run_after_warp_ready &
warp-svc | grep -v INFO