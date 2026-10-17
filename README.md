# Lanrith

Lanrith builds a reusable router OS from Debian, systemd and mkosi. The public
build contains the routing tools and generic runtime. An owner's private
repository supplies hardware selectors, network intent, administrator public
keys and optional integrations. Final assembly creates a new verified root and
UKI signed by that owner.

This repository starts a fresh source and release history. Initial OS builds
are qualification prereleases. Production admission stays closed until the
release has passing native boot, update, recovery and supply-chain evidence.
Publishing source, passing unit tests and signing an artifact do not establish
that a router is ready for production.

## Configuration

Start a **private** repository from [config-template](https://github.com/Lanrith/config-template).
[The minimal example](examples/minimal.yaml) has a DHCP uplink, a dual-stack LAN,
DNS and DHCP. [The segmented example](examples/segmented.yaml) has independent
networks and explicit management access. Both use synthetic addresses,
interface selectors and administrator keys. Replace them before building.

```sh
python3 -m lanrith validate config.yaml
python3 -m lanrith render config.yaml --output rendered
```

The firewall denies inter-network traffic and router administration by default.
The configuration explicitly selects management networks and internet access.
Optional services start only when enabled. No directory, Kubernetes cluster,
remote DNS service or telemetry destination is assumed. Advanced integrations
use reviewed, digest-bound file extensions; configuration cannot run build
hooks. See [configuration and integrations](docs/configuration.md).

## Building

Public CI builds the complete package universe, a neutral root filesystem,
neutral initrd filesystem, compiler tools and the matching builder image.
GitHub Actions reuses authenticated builder and compiler cache data; security
assessment and native qualification run again for each release. Cache misses
fall back to a full build. See [cache admission and clean builds](docs/build-and-trust.md).
[Package policy](security/policy.json) and [package selection](mkosi/packages.json)
are reviewed inputs. [Discovery Bridge](https://github.com/Lanrith/discovery-bridge)
and [Router Policy Agent](https://github.com/Lanrith/router-policy-agent) have
independent repositories and releases. The web console is a separate project.

Owner assembly uses mkosi `BaseTrees=` with the authenticated filesystem
archives. It does not install packages or fetch tools while signing material is
present. The owner chooses NIC selectors, uplink, networks, state and slot
budgets, Secure Boot, TPM or manual state encryption, and recovery console.
x86-64 is the first qualification target; support for a device requires native
results for its profile.

The template provides reviewed update proposals and protected signing jobs.
[Local builds](docs/build-and-trust.md) use the same compiler and contracts with
an owner's existing key-management process.

## Releases and security

Reviewed merges trigger qualification builds. Daily proposals refresh package
inputs at 04:17 UTC. Proposals never bypass review or auto-merge security-policy
changes. Retained releases receive independent advisory rescans; an independent
watchdog reports missing scan success.

Each release provides package inventory, an SPDX SBOM, policy and vulnerability
evidence, immutable source and workflow identities, artifact digests, a matching
builder digest and offline provenance bundles. Consumers verify all selected
artifacts before extracting tools or running the builder. Production admission
requires a fresh inventory-bound security assessment and the recorded SLSA
v1.2 Build L3 and native qualification assessment. See [the trust model](docs/build-and-trust.md)
and [security reporting](SECURITY.md).

An owner-signed update has an independent monotonic deployment sequence and a
configuration digest. Staging protects the mounted root, writes the inactive
verity triplet, publishes its counted UKI last and keeps the accepted default.
A fresh healthy boot and recovery enrollment must pass before acceptance.
[Recovery and operations](docs/operations.md) describes these boundaries.

## Development

Run `python3 -m unittest discover -s tests -v` on Debian with PyYAML and OpenSSL.
`tests/native.py` additionally needs nftables, Unbound, Kea and an isolated
network namespace. CI runs both. Full image and firmware qualification are
separate gates; see [the qualification matrix](docs/qualification.md).

Lanrith source is Apache-2.0. Third-party packages retain their own licenses.
