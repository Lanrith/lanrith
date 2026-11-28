#!/bin/sh
# Run in the verified, dependency-patched upstream source checkout.
set -eu

test "$(go env GOVERSION)" = "$LANRITH_GO_VERSION"
: "${LANRITH_PACKAGE_VERSION:?missing package version}"
python3 /work/go-download.py all
go mod verify
./ttar -C collector/fixtures -x -f collector/fixtures/sys.ttar
./ttar -C collector/fixtures -x -f collector/fixtures/udev.ttar
go test ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=true \
    -ldflags "-X github.com/prometheus/common/version.Version=$LANRITH_PACKAGE_VERSION" \
    -o /work/node_exporter .
python3 /work/collect-notices.py go --output /work/exporter-notices.txt
