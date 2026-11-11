#!/bin/sh
# APT mirror selection does not attach Target-Type to every metadata request.
# Bind the actual accepted InRelease files, not just pre-staged copies, to the
# controller-checked signed bytes before apt-get update can return success.
set -eu
for archive in debian debian-security; do
    suite=$(cat "/etc/apt/lanrith-repositories/$archive/suite")
    case "$suite" in trixie|trixie-security|bookworm|bookworm-security) ;; *) exit 1;; esac
    set -- /var/lib/apt/lists/*"$archive.mirrors_dists_${suite}_InRelease"
    test "$#" -eq 1
    test -f "$1" && test ! -L "$1"
    actual=$(sha256sum "$1")
    expected=$(cat "/etc/apt/lanrith-repositories/$archive/inrelease.sha256")
    test "${actual%% *}" = "$expected"
done
