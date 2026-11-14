"""Synthetic qualification interface data; never native execution evidence."""

from lanrith import dns_qualification


def sources(project):
    for name in dns_qualification.IMPLEMENTATION:
        path = project/name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text('synthetic DNS implementation: '+name)


def report(filesystem_sha256, now, project=None):
    return {'schema': 1, 'test': 'offline-dns-observations', 'result': 'pass', 'assessed_at': now.isoformat(),
        'checks': sorted(dns_qualification.CHECKS), 'external_network': False, 'private_image_qualified': False,
        'image_boot_qualified': False, 'container_cleanup': 'removed', 'container_runtime': 'docker',
        'builder_image_sha256': 'f'*64, 'filesystem_sha256': filesystem_sha256,
        'unbound_sha256': 'c'*64, 'unbound_checkconf_sha256': 'd'*64,
        'base_binaries_sha256': {'usr/sbin/unbound': 'c'*64, 'usr/sbin/unbound-checkconf': 'd'*64},
        'collector_uid': 1802, 'effective_capabilities': 0, 'bounding_capabilities': 0, 'no_new_privileges': True,
        'assembly_sha256': {name: 'e'*64 for name in dns_qualification.ASSEMBLY},
        'source_sha256': dns_qualification.implementation(project) if project is not None else
                         {name: 'b'*64 for name in dns_qualification.IMPLEMENTATION}}
