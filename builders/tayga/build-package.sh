#!/bin/sh
# Run in a clean clone of the locked source. Both the OCI build and offline
# package qualification use this entry point with the same build context.
set -eu
recipe=$(dirname "$(realpath "$0")")
packages=${1:?supply the package output directory}
test "$(git rev-parse HEAD)" = "$TAYGA_SOURCE_COMMIT"
test "$(git describe --exact-match --tags HEAD)" = "$TAYGA_SOURCE_REF"
test -z "$(git status --porcelain)"
git apply "$recipe/complete-udp-checksum.patch"
make TAYGA_VERSION="$TAYGA_DEBIAN_VERSION"
make test
./tayga --help 2>&1 | grep -Fqx "TAYGA version $TAYGA_DEBIAN_VERSION"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cc -std=gnu11 -Wall -Werror -O2 -ffunction-sections -fdata-sections -I. \
    "$recipe/check-udp.c" log.c -Wl,--gc-sections -o "$stage/check-udp"
"$stage/check-udp"

install -D -m 0755 tayga "$stage/root$TAYGA_BINARY"
install -d -m 0755 "$stage/root/DEBIAN" "$packages"
cat > "$stage/root/DEBIAN/control" <<CONTROL
Package: $TAYGA_PACKAGE
Version: $TAYGA_DEBIAN_VERSION
Section: net
Priority: optional
Architecture: amd64
Depends: libc6 (>= 2.38)
Maintainer: Lanrith <root@localhost>
Description: TAYGA with private NAT64 UDP checksum support
CONTROL
test "$(dpkg --print-architecture)" = amd64
package_file="$packages/${TAYGA_PACKAGE}_${TAYGA_DEBIAN_VERSION}_amd64.deb"
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH
dpkg-deb --build --root-owner-group "$stage/root" "$package_file"
test "$(dpkg-deb --field "$package_file" Package)" = "$TAYGA_PACKAGE"
test "$(dpkg-deb --field "$package_file" Version)" = "$TAYGA_DEBIAN_VERSION"
test "$(dpkg-deb --field "$package_file" Architecture)" = amd64
dpkg-deb --fsys-tarfile "$package_file" | tar -t | grep -Fqx ".$TAYGA_BINARY"
sha256sum "$package_file" > "$packages/SHA256SUMS"
