#!/bin/sh
# These .debs were authenticated by Debian's archive signatures and pinned in
# apt-security.json. Do not use the unpatched package manager to fetch its fix.
set -eu
cd /opt/lanrith-apt-bootstrap
sha256sum --check --strict SHA256SUMS
. /etc/os-release
test "$VERSION_CODENAME" = "$(cat distribution)"
version=$(cat version)
library=libapt-pkg7.0
if test "$VERSION_CODENAME" = bookworm; then library=libapt-pkg6.0; fi
current=$(dpkg-query -W -f='${Version}' apt)
if dpkg --compare-versions "$current" lt "$version"; then
    dpkg --install "${library}_${version}_amd64.deb" "apt_${version}_amd64.deb"
fi
current=$(dpkg-query -W -f='${Version}' apt)
dpkg --compare-versions "$current" ge "$version"
library_version=$(dpkg-query -W -f='${Version}' "$library")
dpkg --compare-versions "$library_version" ge "$version"
# A frozen older runtime archive must not downgrade the patched build tools.
printf 'Package: apt apt-utils %s\nPin: version %s\nPin-Priority: 1002\n' "$library" "$current" \
    > /etc/apt/preferences.d/99-lanrith-apt-security
printf 'Lanrith APT security bootstrap: apt=%s library=%s (minimum %s).\n' "$current" "$library_version" "$version"
