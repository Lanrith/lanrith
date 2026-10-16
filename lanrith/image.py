"""Shared mkosi recipes for the neutral runtime and its boot filesystem."""


def base_configuration(snapshot, version, packages):
    return (
        '[Distribution]\nDistribution=debian\nRelease=trixie\nArchitecture=x86-64\n'
        f'Snapshot={snapshot}\n\n[Output]\nFormat=tar\n'
        f'ImageId=lanrith\nImageVersion={version}\nOutput=lanrith-base\nOutputDirectory=/work/output\n'
        'ManifestFormat=json\nCompressOutput=gz\n\n[Content]\nBootable=no\n'
        'WithRecommends=no\nCleanPackageMetadata=yes\nPackages='+','.join(packages)+'\n')


def initrd_configuration(snapshot):
    # Reset mkosi-initrd's filesystem-tool defaults. Kernel modules remain
    # hardware-neutral; userspace tools cover only the supported disk layout.
    packages = ('systemd', 'udev', 'bash', 'less', 'gzip', 'kmod', 'dmsetup',
                'libcryptsetup12', 'libfido2-1', 'dosfstools', 'linux-image-amd64',
                'python3', 'openssl', 'coreutils', 'util-linux', 'fdisk', 'e2fsprogs',
                'cryptsetup-bin', 'systemd-cryptsetup', 'systemd-repart', 'tpm2-tools')
    return (
        '[Include]\nInclude=mkosi-initrd\n'
        '[Distribution]\nDistribution=debian\nRelease=trixie\nArchitecture=x86-64\n'
        f'Snapshot={snapshot}\n'
        '[Output]\nFormat=tar\nOutput=lanrith-initrd-base\nOutputDirectory=/work/output\n'
        'CompressOutput=gz\nManifestFormat=json\n'
        '[Content]\nWithRecommends=no\nWithDocs=no\nCleanPackageMetadata=yes\nRemovePackages=\n'
        'RemoveFiles=/usr/share/locale /usr/lib/python3.*/test /usr/lib/python3.*/idlelib '
        '/boot /vmlinuz* /initrd.img* **/__pycache__ /usr/bin/dpkg* /usr/sbin/dpkg* /usr/lib/dpkg /usr/share/dpkg\n'
        'Packages=\nPackages='+','.join(packages)+'\n')
