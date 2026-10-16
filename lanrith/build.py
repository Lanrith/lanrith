"""Generate mkosi assembly inputs without allowing configuration to install tools."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import uuid

from . import config, extensions, release
from .release import require


def assembly(value, base, destination, *, version, sequence, certificate=None, private_key=None,
             integrations=None, serial_hash=None, initrd_base=None):
    require(not destination.exists() and not destination.is_symlink(), 'Build workspace already exists.')
    require(base.is_file() and not base.is_symlink() and base.resolve() == base.absolute(),
            'Base filesystem must be an admitted canonical archive.')
    require((certificate is None) == (private_key is None), 'Both signing inputs are required together.')
    require(release.VERSION.fullmatch(version) and type(sequence) is int and 1 <= sequence <= 999999999,
            'Invalid image release identity.')
    value = config.normalize(value)
    machine_id = value['hardware'].get('machine_id')
    require(machine_id is not None, 'Set hardware.machine_id once in owner configuration before building.')
    initrd_base = initrd_base or base
    require(initrd_base.is_file() and not initrd_base.is_symlink() and initrd_base.resolve() == initrd_base.absolute(),
            'Initrd filesystem must be an admitted canonical archive.')
    if value['administration']['serial']['enabled']:
        require(serial_hash is not None and serial_hash.is_file() and not serial_hash.is_symlink() and
                not serial_hash.stat().st_mode & 0o077, 'Serial administration requires a private provisioning hash.')
        import re
        require(re.fullmatch(rb'scrypt:32768:8:1:[0-9a-f]{32}:[0-9a-f]{64}\n?', release.read(serial_hash, 512)),
                'Invalid serial provisioning hash.')
    destination.mkdir(mode=0o700, parents=True)
    overlay = destination / 'mkosi.extra'
    digest = config.write(value, overlay)
    base_files, accounts = set(), {}
    if integrations:
        with tarfile.open(base) as archive:
            for member in archive:
                name = member.name.removeprefix('./').rstrip('/')
                if not member.isdir():
                    base_files.add(name)
                if name in ('etc/passwd', 'etc/group'):
                    require(member.isfile() and 0 < member.size <= 1024*1024 and
                            Path(name).name not in accounts, 'Base service account registry is ambiguous.')
                    accounts[Path(name).name] = archive.extractfile(member).read()
    integration = extensions.overlay(value, integrations or {}, overlay, base_files=base_files)
    extensions.account_overlay(accounts, integration['identities'], overlay, value['administration']['username'])
    # The effective intent includes every admitted integration, even when it adds no network fields.
    digest = hashlib.sha256(release.canonical({'configuration': value,
                                             'integrations': integration['digests'],
                                             'serial_provisioning_sha256': release.file_record(serial_hash)['sha256']
                                             if serial_hash else None})).hexdigest()
    (overlay / 'usr/share/lanrith/configuration.sha256').write_text(digest + '\n')
    image_id = value.get('release', {}).get('image_id', 'lanrith')
    installed = {'schema': 1, 'layout': 'ab-verity-v1', 'image_id': image_id, 'machine_id': machine_id,
                 'update_image_id': image_id, 'platform_version': version, 'deployment_sequence': sequence,
                 'uki_name': f'{image_id}_{sequence}.efi', 'state_directory': '/var/lib/lanrith',
                 'certificate': '/usr/share/lanrith/owner.crt', 'esp': 'auto',
                 'integration_health_units': integration['health_units'],
                 'configuration_sha256': digest, 'storage': value['hardware']['storage'],
                 'payload_limits': {'root': value['hardware']['storage']['root_mib']*1024*1024,
                    'verity': max(64, value['hardware']['storage']['root_mib']//16)*1024*1024,
                    'verity-sig': 16384, 'uki': (value['hardware']['storage']['esp_mib']-32)*1024*1024},
                 'boot': value['hardware']['boot'],
                 'active_labels': {role: f'l_{sequence}_{role.replace("-", "_")}' for role in release.ROLES['update']
                                   if role != 'uki'}}
    metadata = overlay / 'usr/share/lanrith'
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata / 'installed.json').write_bytes(release.canonical(installed))
    (overlay/'etc/machine-id').write_text(machine_id+'\n')
    (destination/'mkosi.machine-id').write_text(machine_id+'\n')
    tmpfiles = overlay/'usr/lib/tmpfiles.d/80-lanrith-update.conf'
    tmpfiles.parent.mkdir(parents=True, exist_ok=True)
    tmpfiles.write_text('d /var/lib/lanrith 0700 root root -\n'
                        'd /var/lib/lanrith/update-inbox 0700 root root -\n'
                        f'd /var/tmp/lanrith-update 0700 {value["administration"]["username"]} '
                        f'{value["administration"]["username"]} -\n')
    library = overlay / 'usr/lib/lanrith/lanrith'
    library.mkdir(parents=True)
    for module in ('__init__.py', 'release.py', 'update.py', 'runtime.py', 'factory.py'):
        path = Path(__file__).with_name(module)
        require(path.is_file(), 'A required image runtime module is missing.')
        shutil.copyfile(path, library / module)
    wrapper = overlay / 'usr/bin/lanrith-runtime'
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text('#!/usr/bin/python3\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                       'from lanrith.runtime import main\nsys.exit(main())\n')
    wrapper.chmod(0o755)
    if serial_hash is not None:
        shutil.copyfile(serial_hash, overlay/'etc/security/admin.serial-passphrase.hash')
        (overlay/'etc/security/admin.serial-passphrase.hash').chmod(0o600)
    units = overlay / 'usr/lib/systemd/system'
    units.mkdir(parents=True, exist_ok=True)
    required = ['nftables.service', 'ssh.service', 'systemd-networkd.service'] + integration['health_units']
    for feature, unit in (('dns', 'unbound.service'), ('dhcp4', 'kea-dhcp4-server.service'), ('ntp', 'chrony.service')):
        if value['services'].get(feature, {}).get('enabled'):
            required.append(unit)
    if value['administration']['serial']['enabled']:
        required.append('lanrith-serial-idle-watchdog.service')
    required = sorted(set(required))
    (units / 'lanrith-health.service').write_text(
        '[Unit]\nDescription=Verify local router readiness before boot acceptance\n'
        f'Requires=lanrith-recovery-key.service {" ".join(required)}\n'
        f'After=lanrith-recovery-key.service {" ".join(required)}\nBefore=boot-complete.target\n'
        '\n[Service]\nType=oneshot\nTimeoutStartSec=60s\nExecStart=/usr/bin/lanrith-runtime health\n'
        '\n[Install]\nRequiredBy=boot-complete.target\n')
    (units / 'lanrith-observation.service').write_text(
        '[Unit]\nDescription=Publish accepted boot observation\nDefaultDependencies=no\n'
        'Requires=boot-complete.target\nAfter=boot-complete.target systemd-bless-boot.service\n'
        'Conflicts=shutdown.target\nBefore=shutdown.target\n'
        '\n[Service]\nType=oneshot\nExecStart=/usr/bin/lanrith-runtime publish\n'
        '\n[Install]\nWantedBy=multi-user.target\n')
    wants = overlay / 'etc/systemd/system'
    wants.mkdir(parents=True, exist_ok=True)
    # Factory provisioning owns repartitioning and always supplies the observed
    # disk. Do not let an automatic service select a disk from global labels.
    (wants/'systemd-repart.service').symlink_to('/dev/null')
    for name, text in storage_definitions(value, sequence).items():
        path = overlay/'usr/lib/repart.d'/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    recovery_console = value['hardware']['boot']['recovery_console']
    (units/'lanrith-slot-initialization.service').write_text(
        '[Unit]\nDescription=Verify the installed A/B slot geometry\nRequires=var.mount\n'
        'After=systemd-repart.service var.mount\nBefore=lanrith-recovery-key.service\n'
        '\n[Service]\nType=oneshot\nExecStart=/usr/bin/lanrith-runtime initialize\n'
        '\n[Install]\nRequiredBy=multi-user.target\n')
    (units/'lanrith-recovery-key.service').write_text(
        '[Unit]\nDescription=Record an offline state recovery key\nRequires=var.mount lanrith-slot-initialization.service\n'
        'After=var.mount lanrith-slot-initialization.service\nBefore=multi-user.target\n'
        'ConditionPathExists=!/var/lib/lanrith/recovery-key-enrolled\n'
        '\n[Service]\nType=oneshot\nExecStart=/usr/bin/lanrith-runtime recovery\n'
        f'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/{recovery_console}\n'
        'TTYReset=yes\nTTYVHangup=no\nTimeoutStartSec=infinity\n'
        '\n[Install]\nRequiredBy=multi-user.target\n')
    # The standard boot check runs after multi-user.target. Pull acceptance in
    # through the observer without ordering multi-user after its own completion
    # check. The observer has explicit dependencies so it does not add an
    # implicit Before=multi-user.target edge. Only its boot observation admits
    # the running slot; reaching multi-user.target alone never accepts an image.
    for name in ('lanrith-slot-initialization.service', 'lanrith-recovery-key.service'):
        path = units/'multi-user.target.requires'/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to('/usr/lib/systemd/system/'+name)
    if recovery_console != 'tty0':
        dropin = wants/('serial-getty@'+recovery_console+'.service.d/10-recovery-gate.conf')
        dropin.parent.mkdir(parents=True, exist_ok=True)
        dropin.write_text('[Unit]\nAfter=lanrith-recovery-key.service\n'
                          'ConditionPathExists=/var/lib/lanrith/recovery-key-enrolled\n')
    for directory, unit in [('boot-complete.target.requires', 'lanrith-health.service'),
                            ('boot-complete.target.requires', 'systemd-boot-check-no-failures.service'),
                            ('multi-user.target.wants', 'lanrith-observation.service')] + [
                                ('multi-user.target.wants', unit) for unit in required]:
        # Vendor activation is part of the signed owner policy. Reapplying
        # distribution presets must not remove a required acceptance check.
        path = units / directory / unit
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to('/usr/lib/systemd/system/' + unit)
    for unit in sorted(set(required) | {'lanrith-slot-initialization.service', 'lanrith-recovery-key.service',
                                       'lanrith-health.service', 'lanrith-observation.service',
                                       'lanrith-ssh-host-key.service'}):
        # Replace the base's inactive mask only for explicitly selected health requirements.
        path = wants/unit
        require(not path.exists() and not path.is_symlink(), 'Integration conflicts with a selected service activation.')
        path.symlink_to('/usr/lib/systemd/system/'+unit)
    if value['administration']['serial']['enabled']:
        tty = value['administration']['serial'].get('tty', 'ttyS0')
        (units/'lanrith-serial-idle-watchdog.service').write_text(
            '[Unit]\nDescription=Expire idle serial administration\n'
            'Requires=lanrith-recovery-key.service\nAfter=lanrith-recovery-key.service\n'
            f'Upholds=serial-getty@{tty}.service\n'
            'ConditionPathExists=/var/lib/lanrith/recovery-key-enrolled\n'
            '\n[Service]\nType=exec\nExecStart=/usr/lib/lanrith/serial-idle-watchdog\n'
            'Restart=always\nRestartSec=2s\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n')
        unit = 'serial-getty@'+tty+'.service'
        path = units/'multi-user.target.wants'/unit
        path.symlink_to('/usr/lib/systemd/system/'+unit)
    if certificate is not None:
        require(certificate.is_file() and private_key.is_file(), 'Signing inputs are unavailable.')
        release.public_key(certificate)
        shutil.copyfile(certificate, metadata / 'owner.crt')
    boot = value['hardware']['boot']
    if certificate is not None:
        require(boot.get('secure_boot', True), 'Signed release cannot disable Secure Boot.')
    repart = destination / 'mkosi.repart'
    repart.mkdir()
    storage = value['hardware']['storage']
    (repart / '00-esp.conf').write_text(
        '[Partition]\nType=esp\nFormat=vfat\nCopyFiles=/efi:/\nCopyFiles=/boot:/\n'
        f'SizeMinBytes={storage["esp_mib"]}M\nSizeMaxBytes={storage["esp_mib"]}M\n')
    for index, role in enumerate(('verity-sig', 'verity', 'root'), 10):
        part = 'root' if role == 'root' else 'root-' + role
        verity = {'root': 'data', 'verity': 'hash', 'verity-sig': 'signature'}[role]
        text = f'[Partition]\nType={part}\nLabel=l_{sequence}_{role.replace("-", "_")}\n'
        if role == 'verity-sig':
            # Permanent machine identity must not give successive deployments the
            # same signature-partition UUID as the still-active accepted slot.
            text += 'UUID='+str(uuid.uuid5(uuid.UUID(machine_id), f'{image_id}/{sequence}/{role}'))+'\n'
        elif role == 'verity':
            # Repart can grow the last existing root but cannot move it to make
            # room for a preceding hash partition on first boot.
            capacity = max(64, storage['root_mib']//16)
            text += f'SizeMinBytes={capacity}M\nSizeMaxBytes={capacity}M\n'
        text += f'Verity={verity}\nVerityMatchKey=root\nSplitName={role}\n'
        if role == 'root':
            text += 'Format=erofs\nCopyFiles=/\nExcludeFilesTarget=/var/\nMinimize=best\n'
            if 'root_mib' in storage:
                text += f'SizeMaxBytes={storage["root_mib"]}M\n'
        (repart / f'{index}-{role}.conf').write_text(text)
    initrd = destination/'mkosi.images/initrd'
    initrd.mkdir(parents=True)
    (initrd/'mkosi.conf').write_text(
        '[Output]\nFormat=cpio\nOutput=initrd\n'
        'CompressOutput=zstd\nManifestFormat=\nSplitArtifacts=\n'
        f'\n[Content]\nBaseTrees={initrd_base}\nBootable=no\nMakeInitrd=yes\n')
    (initrd/'mkosi.machine-id').write_text(machine_id+'\n')
    initrd_overlay = initrd/'mkosi.extra'
    (initrd_overlay/'etc').mkdir(parents=True)
    (initrd_overlay/'etc/machine-id').write_text(machine_id+'\n')
    initrd_masks = initrd_overlay/'etc/systemd/system'
    initrd_masks.mkdir(parents=True)
    (initrd_masks/'systemd-repart.service').symlink_to('/dev/null')
    initrd_units = initrd_overlay/'usr/lib/systemd/system'
    initrd_units.mkdir(parents=True)
    initrd_library = initrd_overlay/'usr/lib/lanrith/lanrith'
    shutil.copytree(library, initrd_library)
    entry = initrd_overlay/'usr/bin/lanrith-factory'
    entry.parent.mkdir(parents=True)
    entry.write_text('#!/usr/bin/python3\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                     'from lanrith.factory import main\nsys.exit(main())\n')
    entry.chmod(0o755)
    (initrd_units/'lanrith-factory.service').write_text(
        '[Unit]\nDescription=Verify factory media and explicitly provision the selected disk\n'
        'DefaultDependencies=no\nRequires=initrd-root-fs.target\nAfter=initrd-root-fs.target systemd-udev-trigger.service\n'
        'Before=initrd-udevadm-cleanup-db.service initrd-cleanup.service initrd-switch-root.target shutdown.target\n'
        'Conflicts=shutdown.target\n'
        'OnFailure=emergency.target\n'
        '\n[Service]\nType=oneshot\nExecStart=/usr/bin/lanrith-factory provision\n'
        f'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/{recovery_console}\n'
        'TTYReset=yes\nTTYVHangup=no\nTimeoutStartSec=infinity\n')
    link = initrd_overlay/'usr/lib/systemd/system/initrd-switch-root.target.requires/lanrith-factory.service'
    link.parent.mkdir(parents=True)
    link.symlink_to('../lanrith-factory.service')
    trust_path = initrd_overlay/'etc/verity.d'
    trust_path.mkdir(parents=True)
    if certificate:
        shutil.copyfile(certificate, trust_path/'owner.crt')
    acceleration = value['hardware'].get('acceleration')
    kernel = ''
    if acceleration:
        require(acceleration['hugepages_mib'] % 2 == 0, 'Hugepage allocation must be divisible by 2 MiB.')
        kernel = f' iommu=pt intel_iommu=on amd_iommu=on hugepagesz=2M hugepages={acceleration["hugepages_mib"]//2}'
    # No Packages= or arbitrary hooks are admitted in the final signing phase.
    text = ('[Distribution]\nDistribution=debian\nRelease=trixie\nArchitecture=x86-64\n'
            f'\n[Output]\nFormat=disk\nImageId={image_id}\nImageVersion={sequence}\n'
            f'Output={image_id}_{sequence}\nOutputDirectory={destination / "output"}\n'
            'SplitArtifacts=uki,partitions\nManifestFormat=json\n'
            f'\n[Content]\nBaseTrees={base}\nBootable=yes\nShimBootloader=signed\nInitrds=%O/initrd\n'
            f'KernelCommandLine=console={boot.get("console", "tty0")} systemd.log_target=journal-or-kmsg '
            'systemd.journald.forward_to_console=0 systemd.journald.forward_to_kmsg=0 '
            f'systemd.journald.forward_to_wall=0{kernel}\n'
            '\n[Validation]\n')
    if certificate is None:
        text += 'SecureBoot=no\n'
    else:
        text += (f'Verity=signed\nSecureBoot=yes\nSecureBootKey={private_key}\nSecureBootCertificate={certificate}\n'
                 f'VerityKey={private_key}\nVerityCertificate={certificate}\n')
    (destination / 'mkosi.conf').write_text(text)
    finalize = Path(__file__).parents[1]/'scripts/finalize-image.py'
    require(finalize.is_file(), 'Native final-tree verification is missing.')
    shutil.copyfile(finalize, destination/'mkosi.finalize')
    (destination/'mkosi.finalize').chmod(0o755)
    return {'configuration_sha256': digest, 'platform_version': version,
            'deployment_sequence': sequence, 'image_id': image_id}


def storage_definitions(value, sequence):
    """Expand only the selected installed disk; keep surplus space unallocated."""
    storage = value['hardware']['storage']
    definitions = {}
    capacities = {'verity-sig': '16K', 'verity': str(max(64, storage['root_mib']//16))+'M',
                  'root': str(storage['root_mib'])+'M'}
    definitions['00-esp.conf'] = f'[Partition]\nType=esp\nSizeMinBytes={storage["esp_mib"]}M\nSizeMaxBytes={storage["esp_mib"]}M\n'
    for slot, offset in (('a', 10), ('b', 20)):
        for index, role in enumerate(('verity-sig', 'verity', 'root'), offset):
            kind = 'root' if role == 'root' else 'root-'+role
            label = f'l_{sequence}_{role.replace("-", "_")}' if slot == 'a' else '_empty'
            definitions[f'{index}-{slot}-{role}.conf'] = (
                f'[Partition]\nType={kind}\nLabel={label}\nSizeMinBytes={capacities[role]}\nSizeMaxBytes={capacities[role]}\n')
    # Manual encryption is completed by the explicit installer before first boot.
    encrypt = 'tpm2' if value['hardware']['boot'].get('tpm', 'required') == 'required' else 'key-file'
    definitions['30-var.conf'] = (
        f'[Partition]\nType=var\nLabel=var\nFormat=ext4\nEncrypt={encrypt}\n'
        f'SizeMinBytes={storage["state_mib"]}M\nSizeMaxBytes={storage["state_mib"]}M\n'
        'GrowFileSystem=yes\nPaddingWeight=1000\n')
    return definitions


def run(destination):
    if (destination/'mkosi.extra/usr/share/lanrith/owner.crt').exists():
        manager = Path('/usr/lib/shim/mmx64.efi.signed')
        require(manager.is_file(), 'The admitted builder lacks the signed MOK enrollment manager.')
        result = subprocess.run(['sbverify','--list',str(manager)],capture_output=True,timeout=15)
        require(result.returncode==0, 'MOK enrollment manager signature metadata is unavailable.')
        target=destination/'mkosi.extra/efi/EFI/BOOT/mmx64.efi'
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(manager,target)
    result = subprocess.run(['mkosi', '--directory', str(destination),
                             '--cache-directory', str(destination/'cache'), '--cache-only=always', 'build'],
                            stdin=subprocess.DEVNULL, timeout=3600)
    require(result.returncode == 0, 'mkosi image assembly failed.')
    normalize_factory_entry(destination)


def normalize_factory_entry(destination):
    """Use the same stable UKI identity on factory media and installed updates."""
    installed = json.loads((destination/'mkosi.extra/usr/share/lanrith/installed.json').read_text())
    output = destination/'output'
    disk = output/f'{installed["image_id"]}_{installed["deployment_sequence"]}.raw'
    table = json.loads(subprocess.run(['sfdisk', '--json', str(disk)], check=True,
                                     capture_output=True, timeout=30).stdout)['partitiontable']
    require(table.get('sectorsize', 512) == 512, 'Factory image requires 512-byte logical sectors.')
    parts = [p for p in table['partitions'] if p['type'].lower() == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
    require(len(parts) == 1, 'Factory image must have exactly one EFI partition.')
    image = str(disk)+'@@'+str(parts[0]['start']*512)
    entries = subprocess.run(['mdir', '-b', '-i', image, '::/EFI/Linux/*.efi'], check=True,
                             capture_output=True, text=True, timeout=30).stdout.splitlines()
    require(len(entries) == 1 and entries[0].startswith('::/EFI/Linux/'), 'Factory ESP has ambiguous UKIs.')
    expected = '::/EFI/Linux/'+installed['uki_name']
    if entries[0] != expected:
        subprocess.run(['mren', '-i', image, entries[0], expected], check=True, timeout=30)
    # Verify the renamed entry contains exactly the signed split UKI bytes.
    split = output/f'{installed["image_id"]}_{installed["deployment_sequence"]}.efi'
    with tempfile.TemporaryDirectory(prefix='lanrith-esp-check.', dir=destination) as temporary:
        copied = Path(temporary)/'entry.efi'
        subprocess.run(['mcopy', '-i', image, expected, str(copied)], check=True, timeout=30)
        require(release.file_record(split)['sha256'] == release.file_record(copied)['sha256'],
                'Factory ESP entry differs from the signed split UKI.')


def update_payload(destination, identity, output):
    require(not output.exists(), 'Update output already exists.')
    files = list((destination / 'output').iterdir())
    image_id, sequence = identity['image_id'], identity['deployment_sequence']
    output.mkdir(mode=0o700)
    selected = {}
    disks = [path for path in files if path.name == f'{image_id}_{sequence}.raw']
    require(len(disks) == 1 and disks[0].is_file() and not disks[0].is_symlink(), 'Factory disk is missing.')
    table = json.loads(subprocess.run(['sfdisk', '--json', str(disks[0])], check=True,
                                     capture_output=True, timeout=30).stdout)['partitiontable']['partitions']
    from .update import GUIDS, UUID
    import re
    for role, suffix in (('uki', '.efi'), ('root', '.root.raw'), ('verity', '.verity.raw'),
                         ('verity-sig', '.verity-sig.raw')):
        candidates = [path for path in files if path.name.startswith(f'{image_id}_{sequence}') and path.name.endswith(suffix)]
        require(len(candidates) == 1 and candidates[0].is_file() and not candidates[0].is_symlink(),
                'mkosi did not emit exactly one artifact for each update role.')
        source = candidates[0]
        if role == 'uki':
            name = f'{image_id}_{sequence}.efi'
        else:
            parts = [part for part in table if part.get('name') == f'l_{sequence}_{role.replace("-", "_")}'
                     and part.get('type', '').lower() == GUIDS[role]]
            require(len(parts) == 1 and re.fullmatch(UUID, parts[0].get('uuid', '').lower()),
                    'Factory GPT does not identify the emitted partition.')
            require(source.stat().st_size == parts[0]['size'] * 512,
                    'Split artifact size differs from its GPT partition.')
            name = f'{image_id}_{sequence}_{parts[0]["uuid"].lower()}.{role}.raw'
        shutil.copyfile(source, output / name)
        selected[role] = name
    manifest = release.unsigned_manifest(output, purpose='update', version=identity['platform_version'],
                                         sequence=sequence, configuration_sha256=identity['configuration_sha256'],
                                         files=selected, image_id=image_id)
    with disks[0].open('rb') as raw:
        for artifact in manifest['artifacts']:
            if artifact['role']=='uki':
                continue
            part=next(p for p in table if p.get('name')==f'l_{sequence}_{artifact["role"].replace("-","_")}')
            raw.seek(part['start']*512)
            remaining=part['size']*512
            digest=hashlib.sha256()
            while remaining:
                block=raw.read(min(1024*1024,remaining))
                require(block, 'Factory disk partition is truncated.')
                digest.update(block)
                remaining-=len(block)
            require(digest.hexdigest()==artifact['sha256'], 'Factory disk differs from its split verified-root payload.')
    (output / 'release.json').write_bytes(release.canonical(manifest))
    return manifest


def factory_payload(destination, identity, update, output, *, consume=False):
    require(not output.exists() and not output.is_symlink(), 'Factory output already exists.')
    output.mkdir(mode=0o700)
    value = release.document(release.read(update/'release.json', 65536))
    files = {item['role']: item['name'] for item in value['artifacts']}
    for role,name in files.items():
        source=destination/'output'/(f'{identity["image_id"]}_{identity["deployment_sequence"]}'+
                                    ('.efi' if role=='uki' else '.'+role+'.raw'))
        if consume:
            require(release.file_record(source)['sha256']==release.file_record(update/name)['sha256'],
                    'Factory split data differs from the update payload.')
            shutil.move(source,output/name)
        else:
            shutil.copyfile(update/name, output/name)
    for role, name in (('disk', f'{identity["image_id"]}_{identity["deployment_sequence"]}.raw'),
                       ('initrd', 'initrd.cpio.zst')):
        source = destination/'output'/name
        require(source.is_file() and not source.is_symlink(), 'Factory artifact is missing.')
        (shutil.move if consume else shutil.copyfile)(source, output/name)
        files[role] = name
    value = release.unsigned_manifest(output, purpose='factory', version=identity['platform_version'],
                                     sequence=identity['deployment_sequence'],
                                     configuration_sha256=identity['configuration_sha256'],
                                     files=files, image_id=identity['image_id'])
    (output/'release.json').write_bytes(release.canonical(value))
    return value
