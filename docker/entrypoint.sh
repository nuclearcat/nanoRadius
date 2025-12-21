#!/bin/sh
set -eu

mkdir -p /etc/nanoradius /var/log/nanoradius
touch /var/log/nanoradius/nanoradius.log
if [ "$(id -u)" = "0" ]; then
  chown -R nanoradius:root /etc/nanoradius /var/log/nanoradius
fi

exec "$@"
