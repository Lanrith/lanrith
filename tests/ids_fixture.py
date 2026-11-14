"""Synthetic interface evidence only; this fixture makes no native or release claim."""

from lanrith import ids_qualification


def report(filesystem_sha256, now, project=None):
    sources = (ids_qualification.implementation(project) if project is not None else
               {name: 'b'*64 for name in ids_qualification.IMPLEMENTATION})
    return {'schema': 1, 'test': 'offline-wan-ids', 'result': 'pass', 'assessed_at': now.isoformat(),
            'checks': sorted(ids_qualification.CHECKS), 'external_network': False, 'image_boot_qualified': False,
            'container_cleanup': 'removed', 'container_runtime': 'docker', 'builder_image_sha256': 'f'*64,
            'filesystem_sha256': filesystem_sha256, 'binary_sha256': 'c'*64, 'base_binary_sha256': 'c'*64,
            'base_binary_match': True, 'daemon_working_directory': '/', 'implementation_sha256': sources,
            'detector_uid': 61010, 'no_new_privileges': True,
            'effective_capabilities': 1 << 13, 'bounding_capabilities': 1 << 13,
            'source_sha256': sources['tests/ids_native.py']}


def sources(project):
    for name in ids_qualification.IMPLEMENTATION:
        path = project/name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text('synthetic IDS source: '+name)
