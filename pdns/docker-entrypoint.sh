#!/bin/bash

set -euo pipefail

# Use environmental variables to fill out the pdns.conf file
# This is updated every container start
envtpl --keep-template /etc/powerdns/pdns.conf.tpl
ls -alh /etc/powerdns/pdns.conf

# Continue running Dockerfile CMD
exec "$@"
