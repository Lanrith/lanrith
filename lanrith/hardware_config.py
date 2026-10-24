"""Resolve hardware intent during compilation; never installed in images."""

import fnmatch
import hashlib
import re

from .release import canonical, require


def resolve_ownership(value, facts):
    """Resolve owner intent against a separately authenticated target snapshot.

    This pure function cannot authenticate its caller's evidence. Assembly must
    pin the snapshot digest; binding rechecks identities and isolation in sysfs.
    """
    from .intent import fields, sequence
    fields(facts, {'interfaces', 'hugepages'}, {'interfaces', 'hugepages'})
    observed = sequence(facts['interfaces'], 256, 1)
    for item in observed:
        fields(item, {'name', 'mac', 'pci', 'driver', 'iommu_group', 'iommu_members'},
               {'name', 'mac', 'pci', 'driver', 'iommu_group', 'iommu_members'})
        require(isinstance(item['pci'], str) and
                re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]', item['pci']) and
                type(item['iommu_group']) is int and item['iommu_group'] >= 0 and
                isinstance(item['driver'], str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', item['driver']),
                'Invalid observed PCI identity.')
    bindings = []
    selected = set()
    for interface in value['hardware']['interfaces'].values():
        if interface.get('owner') != 'vpp':
            continue
        require(interface.get('state') == 'down' and set(interface['match']) == {'mac'},
                'Dormant VPP ownership requires an exact hardware selector.')
        matches = [item for item in observed if item['mac'] == interface['match']['mac']]
        require(len(matches) == 1, 'VPP selector has absent or ambiguous hardware evidence.')
        item = matches[0]
        require(item['name'] == interface['name'] and item['pci'] not in selected and
                item['driver'] != 'vfio-pci' and item['iommu_members'] == [item['pci']],
                'VPP evidence must prove an exclusive Linux-owned PCI function.')
        require(sum(other['pci'] == item['pci'] for other in observed) == 1,
                'VPP PCI function exposes multiple or ambiguous interfaces.')
        for other in value['hardware']['interfaces'].values():
            if other is interface:
                continue
            kind, selector = next(iter(other['match'].items()))
            require(kind == 'mac' and selector != item['mac'] or
                    kind == 'driver' and not fnmatch.fnmatchcase(item['driver'], selector),
                    'Another hardware selector may match the VPP-owned device.')
        selected.add(item['pci'])
        bindings.append({**item, 'state': 'down'})
    pages = facts['hugepages']
    fields(pages, {'page_size_mib', 'pages'}, {'page_size_mib', 'pages'})
    require(type(pages['page_size_mib']) is int and pages['page_size_mib'] in (2, 1024) and
            type(pages['pages']) is int and pages['pages'] > 0 and
            2048 <= pages['pages']*pages['page_size_mib'] <= 1048576,
            'VPP memory evidence requires a supported page size and at least 2 GiB.')
    return {'bindings': bindings, 'hugepages': dict(pages) if bindings else None}


def ownership_manifest(value, facts):
    ownership = resolve_ownership(value, facts)
    require(ownership['bindings'], 'Hardware facts were supplied without VPP ownership.')
    require('acceleration' not in value['hardware'], 'Do not combine derived and explicit acceleration settings.')
    return {'schema': 1, 'facts': facts, 'facts_sha256': hashlib.sha256(canonical(facts)).hexdigest(),
            'ownership': ownership}


def ownership_files(value, facts):
    if facts is None:
        return {}
    manifest = ownership_manifest(value, facts)
    return {'usr/share/lanrith/ownership.json': canonical(manifest).decode(),
            'usr/lib/systemd/system/lanrith-hardware-ownership.service':
                '[Unit]\nDescription=Reserve verified dormant VPP hardware\n'
                'Requires=nftables.service\nAfter=nftables.service systemd-udev-trigger.service\n'
                'Before=systemd-networkd.service\n'
                '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                'ExecStartPre=/usr/bin/udevadm settle --timeout=15\n'
                'ExecStart=/usr/bin/python3 -m lanrith.hardware bind-owned\n'
                'Environment=PYTHONPATH=/usr/lib/lanrith\nTimeoutStartSec=60s\n'}


def ownership_kernel(value, facts):
    if facts is None:
        return ''
    pages = ownership_manifest(value, facts)['ownership']['hugepages']
    size = '1G' if pages['page_size_mib'] == 1024 else '2M'
    return f' iommu=pt intel_iommu=on amd_iommu=on default_hugepagesz={size} hugepagesz={size} hugepages={pages["pages"]}'




def manifest(value):
    return {"schema": 1, "interfaces": [dict(item) for item in value["hardware"]["interfaces"].values()
                                      if item.get("owner") != "vpp"],
            "acceleration": value["hardware"].get("acceleration"),
            "vpp_enabled": value["services"].get("vpp", {}).get("enabled", False)}
