#!/bin/sh
# Mirror selection changes transport only. APT still verifies Debian's signed
# metadata and package hashes for the exact controller-staged snapshot dates.
set -eu
cd /opt/lanrith-apt-bootstrap
test "$1" = "$(cat debian.snapshot)"
test "$2" = "$(cat debian-security.snapshot)"
mkdir -p /etc/apt/mirrors
cp -R sandbox/etc/apt/lanrith-repositories /etc/apt/
cp sandbox/etc/apt/verify-lanrith-snapshots /etc/apt/verify-lanrith-snapshots
cp sandbox/etc/apt/apt.conf.d/80-lanrith-transport /etc/apt/apt.conf.d/80-lanrith-transport
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources
cp debian.mirrors debian-security.mirrors /etc/apt/mirrors/
cp sources.list /etc/apt/sources.list
cp snapshot.pref /etc/apt/preferences.d/99-lanrith-snapshot
