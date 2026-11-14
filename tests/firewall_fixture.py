"""Synthetic qualification contract data; never native execution evidence."""

from lanrith import firewall_qualification as gate


def sources(project):
    for name in gate.IMPLEMENTATION:
        path = project/name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text('synthetic firewall implementation: '+name)


def report(filesystem_sha256, now, project=None):
    libraries = {'usr/lib/x86_64-linux-gnu/libnftables.so.1.1.0': 'd'*64}
    return {'schema': 1, 'test': 'offline-firewall-observations', 'result': 'pass', 'assessed_at': now.isoformat(),
        'checks': sorted(gate.CHECKS), 'external_network': False, 'private_image_qualified': False,
        'image_boot_qualified': False, 'container_cleanup': 'removed', 'container_runtime': 'docker',
        'builder_image_sha256': 'f'*64, 'filesystem_sha256': filesystem_sha256, 'generated_service_tested': True,
        'nft_sha256': 'c'*64, 'builder_libraries_sha256': libraries, 'base_userspace_sha256': {gate.NFT: 'c'*64, **libraries},
        'kernel_release': 'synthetic-kernel', 'nft_version': 'nftables vSYNTHETIC',
        'receiver': {'uid': 180, 'capabilities': {key: '0000000000000000' for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb')} |
            {'CapBnd': '0000000000001000', 'NoNewPrivs': '1'}, 'firewall_write_denied': True, 'reconfiguration_denied': True},
        'unconditional_forward_drops': 1100, 'allowed_echoes': 4, 'payload_exported': False,
        'assembly_sha256': {name: 'e'*64 for name in gate.ASSEMBLY},
        'source_sha256': gate.implementation(project) if project is not None else {name: 'b'*64 for name in gate.IMPLEMENTATION}}
