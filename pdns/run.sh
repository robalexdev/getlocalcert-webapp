#!/bin/bash
/usr/sbin/pdns_server \
  --daemon=no \
  --launch=pipe \
  --pipe-abi-version=3 \
  --pipe-command=/app/backend \
  --distributor-threads=10 \
  --pipe-timeout=2000 \
  --consistent-backends=yes \
  --api=no \
  --webserver=no \
  --allow-unsigned-autoprimary=no \
  --disable-axfr=yes \
  --allow-unsigned-notify=no \
  --allow-notify-from= \
  --zone-cache-refresh-interval=0 \
  --default-soa-content="ns1.getlocalcert.net. soa-admin.robalexdev.com. 2023102202 10800 3600 604800 3600"

