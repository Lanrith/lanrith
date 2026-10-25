"""Network-facing base daemons retain only their declared runtime authority."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ServiceHardeningTests(unittest.TestCase):
    def test_unbound_drops_to_a_bounded_seccomp_confined_runtime(self):
        unit = (ROOT/'mkosi/base/mkosi.extra/etc/systemd/system/unbound.service.d/'
                '30-lanrith-hardening.conf').read_text()
        runtime = (ROOT/'mkosi/base/mkosi.extra/etc/unbound/unbound.conf.d/'
                   '99-lanrith-runtime.conf').read_text()
        self.assertIn('NoNewPrivileges=yes\n', unit)
        self.assertIn('CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID '
                      'CAP_NET_BIND_SERVICE\n', unit)
        self.assertIn('ProtectSystem=strict\n', unit)
        self.assertIn('SystemCallFilter=~', unit)
        self.assertIn('MemoryMax=512M\nMemorySwapMax=0\nTasksMax=64\nLimitNOFILE=4096\n', unit)
        self.assertIn('pidfile: "/run/unbound/unbound.pid"', runtime)
        self.assertIn('control-enable: no', runtime)

    def test_kea_keeps_only_dhcp_socket_capabilities(self):
        unit = (ROOT/'mkosi/base/mkosi.extra/etc/systemd/system/kea-dhcp4-server.service.d/'
                '30-lanrith-hardening.conf').read_text()
        self.assertIn('CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW\n', unit)
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW\n', unit)
        self.assertIn('NoNewPrivileges=yes\n', unit)
        self.assertIn('RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_NETLINK AF_UNIX\n', unit)
        self.assertIn('SystemCallFilter=~', unit)
        self.assertIn('MemoryMax=256M\nMemorySwapMax=0\nTasksMax=64\nLimitNOFILE=4096\n', unit)

    def test_chrony_has_a_bounded_clock_service_budget(self):
        unit = (ROOT/'mkosi/base/mkosi.extra/usr/share/lanrith/profiles/etc/systemd/system/'
                'chrony.service.d/20-lanrith-runtime.conf').read_text()
        self.assertIn('NoNewPrivileges=yes\n', unit)
        self.assertIn('MemoryMax=128M\nMemorySwapMax=0\nTasksMax=32\nLimitNOFILE=1024\n', unit)

    def test_boot_health_rejects_missing_confinement_and_alternate_activation(self):
        health = (ROOT/'mkosi/base/mkosi.extra/usr/lib/lanrith/verify-host-hardening').read_text()
        self.assertIn('require_service_hardening unbound.service', health)
        self.assertIn('require_service_hardening kea-dhcp4-server.service', health)
        self.assertIn('require_service_resources unbound.service 536870912 64 4096', health)
        self.assertIn('require_service_resources chrony.service 134217728 32 1024', health)
        self.assertIn('require_service_resources kea-dhcp4-server.service 268435456 64 4096', health)
        self.assertIn('cron.service systemd-hostnamed.service systemd-hostnamed.socket '
                      'ssh.socket sshd@.service', health)


if __name__ == '__main__':
    unittest.main()
