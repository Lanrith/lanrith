"""Generate mkosi assembly inputs without allowing configuration to install tools."""

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tarfile
import uuid

from . import bindings, config, extensions, hardware_config as hardware, release, runtime_plan
from .release import require


def assembly(value, base, destination, *, version, sequence, certificate=None, private_key=None,
             integrations=None, serial_hash=None, initrd_base=None,
             fallback_release=None, fallback_disk_by_id=None, fallback_esp_uuid=None,
             pcr_key=None, pcr_certificate=None, recovery_hash=None,
             target_facts=None, retained_allocations=None):
    for path in (base, destination, certificate, private_key, initrd_base, fallback_release,
                 pcr_key, pcr_certificate, recovery_hash, serial_hash):
        require(path is None or isinstance(path, Path) and path.is_absolute() and
                re.fullmatch(r'/[A-Za-z0-9_./+-]{1,2047}', str(path)),
                'Build paths must be absolute and contain only letters, digits, slash, dot, underscore, plus or hyphen.')
    require(not destination.exists() and not destination.is_symlink(), 'Build workspace already exists.')
    require(base.is_file() and not base.is_symlink() and base.resolve() == base.absolute(),
            'Base filesystem must be an admitted canonical archive.')
    require((certificate is None) == (private_key is None), 'Both signing inputs are required together.')
    require(release.VERSION.fullmatch(version) and type(sequence) is int and 1 <= sequence <= 999999999,
            'Invalid image release identity.')
    value = config.normalize(value)
    # Fail before creating a workspace if hardware evidence or runtime support
    # is missing. Configuration and facts are independently bound in the digest.
    config.render(value, target_facts=target_facts, retained_allocations=retained_allocations)

    from . import boot_policy
    require((pcr_key is None) == (pcr_certificate is None), 'Both PCR signing inputs are required together.')
    public = None
    if certificate is not None and value['hardware']['boot'].get('tpm', 'required') == 'required':
        pcr_key, pcr_certificate = pcr_key or private_key, pcr_certificate or certificate
        public = boot_policy.public_key(pcr_key, pcr_certificate)
    else:
        require(pcr_key is None, 'PCR signing requires a signed TPM image.')
    fallback_binding = None
    fallback_inputs = (fallback_release, fallback_disk_by_id, fallback_esp_uuid)
    if any(item is not None for item in fallback_inputs):
        require(all(item is not None for item in fallback_inputs) and certificate is not None and
                isinstance(fallback_release, Path) and fallback_release.is_absolute() and
                fallback_release.resolve() == fallback_release and fallback_release.is_dir(),
                'Fallback binding requires a signed release, disk and ESP.')
        from . import early_failure, repair
        image_id = value.get('release', {}).get('image_id', 'lanrith')
        observation = repair.signed_fallback_binding(fallback_release, certificate, image_id=image_id)
        fallback_binding = {'disk_by_id': fallback_disk_by_id, 'esp_uuid': fallback_esp_uuid,
                            'release': observation['fallback']}
        early_failure.validate_fallback_binding(fallback_binding, image=image_id, current_sequence=sequence)
    machine_id = value['hardware'].get('machine_id')
    require(machine_id is not None, 'Set hardware.machine_id once in owner configuration before building.')
    initrd_base = initrd_base or base
    require(initrd_base.is_file() and not initrd_base.is_symlink() and initrd_base.resolve() == initrd_base.absolute(),
            'Initrd filesystem must be an admitted canonical archive.')
    if value['administration']['serial']['enabled']:
        require(serial_hash is not None and serial_hash.is_file() and not serial_hash.is_symlink() and
                not serial_hash.stat().st_mode & 0o077, 'Serial administration requires a private provisioning hash.')
        require(re.fullmatch(rb'scrypt:32768:8:1:[0-9a-f]{32}:[0-9a-f]{64}\n?', release.read(serial_hash, 512)),
                'Invalid serial provisioning hash.')
    if value['administration']['root_access'] == 'disabled':
        require(serial_hash is None, 'Root-disabled images cannot include a serial-login credential.')
    destination.mkdir(mode=0o700, parents=True)
    overlay = destination / 'mkosi.extra'
    digest = config.write(value, overlay, target_facts=target_facts, retained_allocations=retained_allocations)
    loader = overlay/'efi/loader/loader.conf'
    loader.parent.mkdir(parents=True, exist_ok=True)
    loader.write_text('timeout 5\neditor no\nauto-firmware no\n')
    base_files, accounts = set(), {}
    if integrations or value.get('runtime', {}).get('service_identities'):
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
    bindings.verify_accounts(value, accounts, overlay)
    # The effective intent includes every admitted integration, even when it adds no network fields.
    boot_inputs = {}
    if public is not None:
        boot_inputs['pcr_public_key_sha256'] = hashlib.sha256(public).hexdigest()
    if recovery_hash is not None:
        boot_inputs['recovery_credential_sha256'] = release.file_record(recovery_hash)['sha256']
    if fallback_binding is not None:
        boot_inputs['fallback_binding'] = fallback_binding
    digest = config.effective_digest(value, integration['digests'],
        release.file_record(serial_hash)['sha256'] if serial_hash else None,
        target_facts=target_facts, retained_allocations=retained_allocations, boot_inputs=boot_inputs)
    (overlay / 'usr/share/lanrith/configuration.sha256').write_text(digest + '\n')
    image_id = value.get('release', {}).get('image_id', 'lanrith')
    installed = {'schema': 1, 'layout': 'ab-verity-v1', 'image_id': image_id, 'machine_id': machine_id,
                 'update_image_id': image_id, 'platform_version': version, 'deployment_sequence': sequence,
                 'uki_name': f'{image_id}_{sequence}.efi', 'state_directory': '/var/lib/lanrith',
                 'certificate': '/usr/share/lanrith/owner.crt', 'esp': 'auto',
                 'operator': value['administration']['username'],
                 'root_access': value['administration']['root_access'],
                 'integration_health_units': integration['health_units'],
                 'extension_credential_catalogs': integration['credential_catalogs'],
                 'configuration_sha256': digest, 'storage': value['hardware']['storage'],
                 'payload_limits': {'root': value['hardware']['storage']['root_mib']*1024*1024,
                    'verity': max(64, value['hardware']['storage']['root_mib']//16)*1024*1024,
                    'verity-sig': 16384, 'uki': (value['hardware']['storage']['esp_mib']-32)*1024*1024},
                 'boot': value['hardware']['boot'], 'watchdog': value['hardware']['watchdog'],
                 'active_labels': {role: f'l_{sequence}_{role.replace("-", "_")}' for role in release.ROLES['update']
                                   if role != 'uki'}}
    credential_manifest = overlay/'usr/share/lanrith/credentials.json'
    installed['credential_catalog_sha256'] = (hashlib.sha256(credential_manifest.read_bytes()).hexdigest()
                                               if credential_manifest.is_file() else None)
    if certificate is not None:
        installed['image_contract'] = boot_policy.contract(value, base, certificate, public, integration['digests'])
        installed['image_contract']['recovery'] = ({'image_id': image_id, 'sequence': sequence,
            'binding': fallback_binding} if fallback_binding else None)
    if public is not None:
        installed['tpm_policy'] = boot_policy.install(overlay, public)
    if fallback_binding is not None:
        from . import image_contract
        previous = release.verify(fallback_release, certificate, purpose='update', image_id=image_id)
        require('image_contract' in previous, 'Recovery fallback lacks a state compatibility contract.')
        image_contract.compatible(installed['image_contract'], previous['image_contract'])
        installed['recovery_state'] = {'image_contract': image_contract.core(installed['image_contract']),
            'fallback_contract': image_contract.core(previous['image_contract']), 'tpm_policy': installed.get('tpm_policy'),
            'state_directory': installed['state_directory']}
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
    for module in ('__init__.py', 'release.py', 'update.py', 'runtime.py', 'factory.py', 'hardware.py',
                   'service_runtime.py', 'routing_runtime.py', 'dns_runtime.py',
                   'dns_observations_runtime.py', 'dns_metadata.py',
                   'translation_runtime.py', 'nat64_runtime.py', 'nat64_packets.py', 'nat64_allocations.py',
                   'metrics_runtime.py', 'router_metrics_runtime.py', 'ntp_health_runtime.py', 'directory_runtime.py', 'policy_runtime.py',
                   'radius_runtime.py', 'kea_runtime.py', 'logs_runtime.py', 'systemd_credential.py', 'credential_values.py', 'credential_store.py',
                   'credential_operation.py', 'extension_credential_values.py', 'extension_credential_operation.py',
                   'boot_health.py',
                   'fancontrol_runtime.py', 'image_contract.py', 'early_failure.py', 'repair.py',
                   'early_unlock.py', 'tpm_migration.py', 'measured_boot.py', 'security_profile.py',
                   'image_operation.py', 'steady_recovery.py'):
        path = Path(__file__).with_name(module)
        require(path.is_file(), 'A required image runtime module is missing.')
        shutil.copyfile(path, library / module)
    # Keep native transaction recovery imports available even without SNMP.
    # None of these helpers activates a daemon or provisioning endpoint.
    helpers = Path(__file__).resolve().parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith'
    for name in ('snmp_credentials.py', 'snmp_service.py', 'credential_runtime.py', 'systemd_service.py'):
        shutil.copyfile(helpers/name, overlay/'usr/lib/lanrith'/name)
    wrapper = overlay / 'usr/bin/lanrith-runtime'
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text('#!/usr/bin/python3\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                       'from lanrith.runtime import main\nsys.exit(main())\n')
    wrapper.chmod(0o755)
    fan_wrapper = overlay / 'usr/lib/lanrith/fancontrol-runtime'
    fan_wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                           'from lanrith.fancontrol_runtime import main\nsys.exit(main())\n')
    fan_wrapper.chmod(0o755)
    if value.get('observability', {}).get('metrics', {}).get('enabled'):
        metrics_wrapper = overlay/'usr/lib/lanrith/router-metrics'
        metrics_wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                                   'from lanrith.router_metrics_runtime import main\nsys.exit(main())\n')
        metrics_wrapper.chmod(0o755)
        if value['services']['ntp']['enabled']:
            ntp_wrapper = overlay/'usr/lib/lanrith/ntp-health'
            ntp_wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                                   'from lanrith.ntp_health_runtime import main\nsys.exit(main())\n')
            ntp_wrapper.chmod(0o755)
        if value.get('identity', {}).get('policy', {}).get('enabled'):
            directory_wrapper = overlay/'usr/lib/lanrith/directory-health'
            directory_wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                                         'from lanrith.directory_runtime import main\nsys.exit(main())\n')
            directory_wrapper.chmod(0o755)
    if value.get('identity', {}).get('policy', {}).get('enabled'):
        policy_wrapper = overlay / 'usr/lib/lanrith/policy-runtime'
        policy_wrapper.write_text('#!/usr/bin/python3\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                                  'from lanrith.policy_runtime import main\nsys.exit(main())\n')
        policy_wrapper.chmod(0o755)
    if value.get('identity', {}).get('radius', {}).get('enabled'):
        radius_wrapper = overlay / 'usr/lib/lanrith/radius-runtime'
        radius_wrapper.write_text('#!/usr/bin/python3\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                                  'from lanrith.radius_runtime import main\nsys.exit(main())\n')
        radius_wrapper.chmod(0o755)
    if value.get('observability', {}).get('logs', {}).get('enabled'):
        logs_wrapper = overlay / 'usr/lib/lanrith/logs-runtime'
        logs_wrapper.write_text('#!/usr/bin/python3\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                                'from lanrith.logs_runtime import main\nsys.exit(main())\n')
        logs_wrapper.chmod(0o755)

    operator_wrapper = overlay/'usr/bin/lanrith-image'
    operator_wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                                'from lanrith.image_operation import main\nsys.exit(main())\n')
    operator_wrapper.chmod(0o755)
    credential_wrapper = overlay/'usr/bin/lanrith-credentials'
    credential_wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
                                  'from lanrith.credential_operation import main\nsys.exit(main())\n')
    credential_wrapper.chmod(0o755)
    extension_credential_wrapper = overlay/'usr/bin/lanrith-extension-credentials'
    extension_credential_wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
        'from lanrith.extension_credential_operation import main\nsys.exit(main())\n')
    extension_credential_wrapper.chmod(0o755)
    if serial_hash is not None:
        shutil.copyfile(serial_hash, overlay/'etc/security/admin.serial-passphrase.hash')
        (overlay/'etc/security/admin.serial-passphrase.hash').chmod(0o600)
    units = overlay / 'usr/lib/systemd/system'
    units.mkdir(parents=True, exist_ok=True)
    if integration['start_units']:
        (units/'lanrith-extension-start.service').write_text(
            '[Unit]\nDescription=Start admitted optional integrations after core acceptance\n'
            'DefaultDependencies=no\nRequires=boot-complete.target lanrith-observation.service\n'
            'After=boot-complete.target lanrith-observation.service\n'
            'Conflicts=shutdown.target\nBefore=shutdown.target\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStart=/usr/bin/systemctl --no-block start -- '+' '.join(integration['start_units'])+'\n'
            'TimeoutStartSec=10s\nCapabilityBoundingSet=\nNoNewPrivileges=yes\n'
            'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n'
            'RestrictAddressFamilies=AF_UNIX\nRestrictNamespaces=yes\n'
            'MemoryMax=32M\nTasksMax=8\nLimitNOFILE=64\n')
        activation = units/'multi-user.target.wants/lanrith-extension-start.service'
        activation.parent.mkdir(parents=True, exist_ok=True)
        activation.symlink_to('../lanrith-extension-start.service')
    required = runtime_plan.required_units(value, target_facts=target_facts,
                                           integrations=integration['health_units'])
    (metadata/'health.json').write_bytes(release.canonical(
        runtime_plan.health(value, target_facts=target_facts, integrations=integration['health_units'])))
    if value.get('observability', {}).get('metrics', {}).get('enabled'):
        metric_policy = json.loads((metadata/'router-metrics.json').read_bytes())
        metric_policy['units'] = required
        (metadata/'router-metrics.json').write_bytes(release.canonical(metric_policy))
    # These helpers may come from an older admitted base. Replace every consumer
    # together with its generated administration contract.
    for name in ('ensure-ssh-host-key', 'verify-serial-passphrase', 'serial-idle-watchdog'):
        helper = Path(__file__).resolve().parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith'/name
        shutil.copyfile(helper, overlay/'usr/lib/lanrith'/name)
        (overlay/'usr/lib/lanrith'/name).chmod(0o755)
    if value.get('observability', {}).get('snmp', {}).get('enabled'):
        # Replace the complete helper policy consumer, including its shared
        # activation dependencies, when assembling on an older admitted base.
        for name in ('snmp-runtime', 'snmp_service.py', 'snmp_credentials.py',
                     'credential_runtime.py', 'systemd_service.py'):
            source = Path(__file__).resolve().parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith'/name
            target = overlay/'usr/lib/lanrith'/name
            shutil.copyfile(source, target)
            target.chmod(0o755 if name == 'snmp-runtime' else 0o644)
    (units/'lanrith-image-operation.socket').write_text(
        '[Unit]\nDescription=Operator image admission socket\n'
        '\n[Socket]\nListenStream=/run/lanrith-image-operation.sock\n'
        f'SocketUser={value["administration"]["username"]}\nSocketMode=0600\n'
        'Accept=yes\nMaxConnections=4\nBacklog=4\nRemoveOnStop=yes\n'
        '\n[Install]\nWantedBy=sockets.target\n')
    (units/'lanrith-image-operation@.service').write_text(
        '[Unit]\nDescription=Bounded operator image operation\n'
        'CollectMode=inactive-or-failed\n'
        'RequiresMountsFor=/var/lib/lanrith /var/tmp/lanrith-update\n'
        '\n[Service]\nType=exec\nExecStart=/usr/bin/lanrith-image serve\n'
        'ExecStopPost=/usr/bin/lanrith-image cancel-request\n'
        'StandardInput=socket\nStandardOutput=journal\nStandardError=journal\n'
        'UMask=0077\nNoNewPrivileges=yes\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n'
        'LockPersonality=yes\nMemoryDenyWriteExecute=yes\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n'
        'SystemCallArchitectures=native\nTasksMax=16\nMemoryMax=256M\nLimitNOFILE=128\n'
        'RuntimeMaxSec=1200\nTimeoutStopSec=30\nKillMode=control-group\n')
    (units/'lanrith-image-completion.service').write_text(
        '[Unit]\nDescription=Accept the authorized image or return to its accepted fallback\n'
        'DefaultDependencies=no\nRequires=local-fs.target\nAfter=local-fs.target\n'
        'After=lanrith-recovery-key.service\n'
        'Before=shutdown.target\nConflicts=shutdown.target\n'
        '\n[Service]\nType=exec\nExecStart=/usr/bin/lanrith-image complete\n'
        'ExecStopPost=/usr/bin/lanrith-image fallback\n'
        'UMask=0077\nNoNewPrivileges=yes\nTasksMax=16\nMemoryMax=128M\n'
        'TimeoutStopSec=900\nRuntimeMaxSec=1200\n'
        '\n[Install]\nWantedBy=multi-user.target\n')
    for target, unit in (('sockets.target.wants', 'lanrith-image-operation.socket'),
                         ('multi-user.target.wants', 'lanrith-image-completion.service')):
        activation = units/target/unit
        activation.parent.mkdir(parents=True, exist_ok=True)
        activation.symlink_to('../'+unit)
    if installed['credential_catalog_sha256'] is not None:
        activation = units/'sockets.target.wants/lanrith-credentials.socket'
        activation.symlink_to('../lanrith-credentials.socket')
    for extension in installed['extension_credential_catalogs']:
        unit = 'lanrith-extension-credential-'+extension+'.socket'
        (units/'sockets.target.wants'/unit).symlink_to('../'+unit)
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
    # Core confinement must also reach owners assembling on an older admitted
    # base. Keep one source for both the neutral base and every owner overlay.
    policies = Path(__file__).resolve().parents[1]/'mkosi/base/mkosi.extra/etc/systemd/system'
    for unit in ('unbound.service', 'kea-dhcp4-server.service', 'chrony.service', 'dbus.service'):
        name = unit+'.d/30-lanrith-hardening.conf'
        target = wants/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(policies/name, target)
    state_mount = wants/'var.mount.d/10-lanrith-state.conf'
    state_mount.parent.mkdir(parents=True, exist_ok=True)
    state_mount.write_text('[Mount]\nOptions=nodev,nosuid,noexec\n')
    # systemd-gpt-auto-generator creates the ESP mount dynamically. Keep it
    # read-only and non-executable outside admitted boot and update mutations.
    # Supply both conventional mount names; only the generated unit is used.
    for mount in ('efi', 'boot'):
        dropin = wants/f'{mount}.mount.d/10-lanrith-read-only.conf'
        dropin.parent.mkdir(parents=True, exist_ok=True)
        dropin.write_text('[Mount]\nOptions=umask=0077,ro,nodev,nosuid,noexec\n')
    blessing = wants/'systemd-bless-boot.service.d/10-lanrith-esp.conf'
    blessing.parent.mkdir(parents=True, exist_ok=True)
    blessing.write_text('[Service]\nExecStart=\nExecStart=/usr/bin/lanrith-runtime bless\n')
    # Retain the vendor unit's early-boot dependencies and conditions. Its
    # native bootctl command needs the same bounded write window as blessing.
    seed = wants/'systemd-boot-random-seed.service.d/10-lanrith-esp.conf'
    seed.parent.mkdir(parents=True, exist_ok=True)
    seed.write_text('[Service]\nExecStart=\nExecStart=/usr/bin/lanrith-runtime refresh-boot-seed\n')
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
    auxiliaries = ({'lanrith-policy-helper-requests.socket', 'lanrith-policy-helper-status.socket'}
                   if value.get('identity', {}).get('policy', {}).get('enabled') else set())
    for unit in sorted(set(required) | auxiliaries | {'lanrith-slot-initialization.service', 'lanrith-recovery-key.service',
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
    # The failure identity is signed in the initrd; it does not depend on
    # mounting the candidate root or include the owner's build-time YAML.
    failure_path = initrd_overlay/'usr/share/lanrith/initrd-failure.json'
    failure_path.parent.mkdir(parents=True, exist_ok=True)
    failure_identity = {key: installed[key] for key in ('image_id', 'deployment_sequence', 'uki_name')}
    if fallback_binding is not None:
        failure_identity['fallback_binding'] = fallback_binding
        failure_identity['steady_state'] = installed['recovery_state']
    failure_path.write_bytes(release.canonical(failure_identity))
    watchdog = value['hardware']['watchdog']
    timeout = 'off' if watchdog['mode'] == 'disabled' else str(watchdog['timeout_seconds'])+'s'
    for tree in (overlay, initrd_overlay):
        path = tree/'usr/lib/systemd/system.conf.d/60-lanrith-watchdog.conf'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('[Manager]\nWatchdogDevice='+watchdog['device']+'\n'
                        'RuntimeWatchdogSec='+timeout+'\n'+
                        ('RebootWatchdogSec=off\n' if watchdog['mode'] == 'disabled' else ''))
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
        'DefaultDependencies=no\nRequires=initrd-root-fs.target\n'
        'After=initrd-root-fs.target systemd-udev-trigger.service systemd-pcrphase-initrd.service\n'
        'Before=initrd-udevadm-cleanup-db.service initrd-cleanup.service initrd-switch-root.target shutdown.target\n'
        'Conflicts=shutdown.target\n'
        'OnFailure=lanrith-initrd-failure.service\nOnFailureJobMode=isolate\n'
        '\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/lanrith-factory provision\n'
        f'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/{recovery_console}\n'
        'TTYReset=yes\nTTYVHangup=no\nTimeoutStartSec=300s\n')
    (initrd_units/'lanrith-initrd-failure.service').write_text(
        '[Unit]\nDescription=Return a failed candidate to its accepted default\nDefaultDependencies=no\nAllowIsolate=yes\n'
        'OnFailure=emergency.target\nOnFailureJobMode=isolate\n'
        '\n[Service]\nType=oneshot\nExecStart=/usr/bin/lanrith-factory failed\n'
        'TimeoutStartSec=900s\nStandardOutput=journal+console\nStandardError=journal+console\n')
    emergency = initrd_units/'emergency.service.d/60-lanrith-recovery.conf'
    emergency.parent.mkdir(parents=True)
    emergency.write_text('[Service]\nType=exec\nExecStart=\nExecStart=/usr/bin/lanrith-factory emergency\n'
                         'StandardInput=null\nStandardOutput=journal+console\nStandardError=journal+console\n')
    link = initrd_overlay/'usr/lib/systemd/system/initrd-switch-root.target.requires/lanrith-factory.service'
    link.parent.mkdir(parents=True)
    link.symlink_to('../lanrith-factory.service')
    # The distribution switch-root service only Wants its target. A failed
    # requirement of that target must also prevent the service switching root.
    boundary = initrd_units/'initrd-switch-root.service.d/60-lanrith-provisioning.conf'
    boundary.parent.mkdir(parents=True)
    boundary.write_text('[Unit]\nRequires=lanrith-factory.service\nAfter=lanrith-factory.service\n')
    # Start before initrd cleanup stops the PCR phase service and extends
    # leave-initrd. The switch-root dependency alone is too late.
    early_boundary = initrd_units/'initrd.target.d/60-lanrith-provisioning.conf'
    early_boundary.parent.mkdir(parents=True)
    early_boundary.write_text('[Unit]\nRequires=lanrith-factory.service\nAfter=lanrith-factory.service\n')
    trust_path = initrd_overlay/'etc/verity.d'
    trust_path.mkdir(parents=True)
    if certificate:
        shutil.copyfile(certificate, trust_path/'owner.crt')
    if public is not None:
        for tree in (overlay, initrd_overlay):
            for name in ('firmware-code', 'firmware-config', 'secureboot-policy', 'secureboot-authority',
                         'machine-id', 'file-system', 'make-policy', 'kernel-code', 'kernel-config'):
                guard = tree/f'etc/systemd/system/systemd-pcrlock-{name}.service.d/60-lanrith.conf'
                guard.parent.mkdir(parents=True, exist_ok=True)
                guard.write_text('[Unit]\nConditionPathExists=/usr/share/lanrith/enable-pcrlock-policy\n')
    acceleration = value['hardware'].get('acceleration')
    kernel = hardware.ownership_kernel(value, target_facts)
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
    if public is not None:
        text += (f'SignExpectedPcr=yes\nSignExpectedPcrKey={pcr_key}\n'
                 f'SignExpectedPcrCertificate={pcr_certificate}\nSignInitrdPCRs=no\n')
    (destination / 'mkosi.conf').write_text(text)
    finalize = Path(__file__).parents[1]/'scripts/finalize-image.py'
    require(finalize.is_file(), 'Native final-tree verification is missing.')
    boundary = finalize.with_name('runtime-boundary.py').read_text().split('\ndef main():', 1)[0]
    root_access = finalize.with_name('root-access.py')
    require(root_access.is_file(), 'Root-access finalization policy is missing.')
    hardening = root_access.read_text().split('\ndef main():', 1)[0]
    selected = json.dumps(value['administration']['root_access'])
    (destination/'mkosi.finalize').write_text(
        boundary+'\n'+hardening+'\nROOT_ACCESS = '+selected+'\n'+finalize.read_text())
    (destination/'mkosi.finalize').chmod(0o755)
    if recovery_hash is not None:
        from . import recovery_failure_build
        recovery_failure_build.prepare(destination, credential=recovery_hash,
            tty=value['hardware']['boot']['recovery_console'], base=base, initrd_base=initrd_base,
            steady=certificate is not None)
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
    return _payload(destination, identity, output, recovery=False)


def recovery_payload(destination, identity, output):
    return _payload(destination, identity, output, recovery=True)


def _payload(destination, identity, output, *, recovery):
    marker = destination/'RECOVERY-ASSEMBLY'
    if recovery:
        require(marker.is_file() and not marker.is_symlink() and
                (destination/'mkosi.images/initrd/mkosi.extra/usr/share/lanrith/recovery-console.json').is_file() and
                not (destination/'mkosi.images/initrd/mkosi.extra/usr/bin/lanrith-factory').exists(),
                'Recovery export requires a dedicated recovery assembly.')
    else:
        require(not marker.exists() and not marker.is_symlink(),
                'A recovery assembly cannot be exported as an update.')
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
    if recovery:
        for role, name in (('disk', disks[0].name), ('initrd', 'initrd.cpio.zst')):
            source = destination/'output'/name
            require(source.is_file() and not source.is_symlink(), 'Recovery artifact is missing.')
            shutil.copyfile(source, output/name)
            selected[role] = name
    manifest = release.unsigned_manifest(output, purpose='recovery' if recovery else 'update', version=identity['platform_version'],
                                         sequence=sequence, configuration_sha256=identity['configuration_sha256'],
                                         files=selected, image_id=image_id,
                                         image_contract=None if recovery else json.loads((destination/'mkosi.extra/usr/share/lanrith/installed.json').read_bytes()).get('image_contract'))
    with disks[0].open('rb') as raw:
        for artifact in manifest['artifacts']:
            if artifact['role'] not in GUIDS:
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
    require(not (destination/'RECOVERY-ASSEMBLY').exists() and
            not (destination/'RECOVERY-ASSEMBLY').is_symlink(),
            'A recovery assembly cannot be exported as factory media.')
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
                                     files=files, image_id=identity['image_id'], image_contract=value.get('image_contract'))
    (output/'release.json').write_bytes(release.canonical(value))
    return value
