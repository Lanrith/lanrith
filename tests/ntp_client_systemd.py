#!/usr/bin/python3
"""Exercise client acceptance, path loss and holdover with a clock-disabled router in an offline VM."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.request import urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import build, config, ntp_health_runtime, service_runtime
from chrony_systemd import WAN4, ctl, selected, wait
from ntp_health_native import role
from unbound_native import network, run, write


def timer_outages(platform):
    observer = 'lanrith-ntp-health.timer'
    collector = 'lanrith-router-metrics.timer'
    directory = '/var/lib/node_exporter/textfile_collector'
    # The assembled collector depends on var.mount. Model that mount without
    # replacing the guest's existing /var content.
    run('mount', '--bind', '/var', '/var')
    wait(lambda: run('systemctl', 'is-active', 'var.mount', check=False).returncode == 0)
    exporter = subprocess.Popen([*role('nobody'), platform/'usr/bin/prometheus-node-exporter',
                                 '--web.listen-address=127.0.0.1:19100', '--collector.disable-defaults',
                                 '--collector.textfile', '--collector.textfile.directory='+directory],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def scrape():
        with urlopen('http://127.0.0.1:19100/metrics', timeout=2) as response:
            return response.read(2*1024*1024).decode()
    def sample(text, name):
        prefix = 'lanrith_router_'+name+' '
        return next((float(line[len(prefix):]) for line in text.splitlines() if line.startswith(prefix)), None)
    query = 'metrics_query_success{collector="chrony"}'
    try:
        run('systemctl', 'start', observer, collector)
        time.sleep(1)
        wait(lambda: sample(scrape(), query) == 1, 48)
        run('systemctl', 'stop', observer)
        run('systemctl', '--wait', 'start', 'lanrith-ntp-health.service')
        last = json.loads(ntp_health_runtime.OUTPUT.read_text())
        wait(lambda: sample(scrape(), query) == 0, 155)
        assert json.loads(ntp_health_runtime.OUTPUT.read_text()) == last
        assert sample(scrape(), 'chrony_synchronised') is None
        print('observer stopped, collector expired observation after',
              round(time.time()-last['observed_timestamp_seconds'], 1), 'seconds', flush=True)
        run('systemctl', 'start', observer)
        wait(lambda: sample(scrape(), query) == 1, 80)
        run('systemctl', 'stop', collector)
        wait(lambda: run('systemctl', 'is-active', 'lanrith-router-metrics.service', check=False).returncode != 0)
        held = sample(scrape(), 'metrics_collection_timestamp_seconds')
        wait(lambda: time.time()-held > 121, 130)
        text = scrape()
        assert sample(text, 'metrics_collection_timestamp_seconds') == held and sample(text, query) == 1
        assert ntp_health_runtime.read_observation()['observed_timestamp_seconds'] > held
        print('collector stopped, exporter still serves collection aged', round(time.time()-held, 1), flush=True)
        run('systemctl', 'start', collector)
        wait(lambda: sample(scrape(), 'metrics_collection_timestamp_seconds') > held and sample(scrape(), query) == 1, 45)
        print('independently restored timers and fresh scrape', flush=True)
    finally:
        exporter.terminate()
        exporter.wait(timeout=5)


def qualify(*, timers=False):
    assert Path('/proc/1/comm').read_text().strip() == 'systemd' and run('systemd-detect-virt', '--vm').stdout.strip()
    assert not Path('/usr/share/lanrith/installed.json').exists()
    assert {r['ifname'] for r in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    run('systemctl', 'stop', 'chrony')
    platform = Path('/opt/fixture-platform')
    for name in ('usr/sbin/chronyd', 'usr/bin/chronyc', 'usr/lib/systemd/system/chrony.service'):
        run('mount', '--bind', platform/name, '/'+name)
    print(run('chronyd', '-v').stdout.strip(), flush=True)
    work = Path('/run/ntp-client-test')
    work.mkdir()
    network('wan', '198.51.100.1', WAN4)
    network('lan', '192.168.10.1', '192.168.10.20')
    run('ip', '-6', 'addr', 'add', 'fd42:1000:1000:10::1/64', 'dev', 'lan', 'nodad')
    run('ip', '-n', 'lan', 'addr', 'add', 'fd42:1000:1000:10::20/64', 'dev', 'eth0', 'nodad')
    run('ip', '-n', 'lan', '-6', 'route', 'add', 'default', 'via', 'fd42:1000:1000:10::1')
    run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    raw = yaml.safe_load((ROOT/'examples/minimal.yaml').read_text())
    raw['services']['ntp'] = {'enabled': True, 'upstreams': [{'type': 'server', 'address': WAN4}]}
    raw['observability'] = {'metrics': {'enabled': True, 'clients': [{'network': 'home'}]}}
    profile = work/'profile.yaml'
    write(profile, yaml.safe_dump(raw))
    value = config.load(profile)
    base = work/'base.tar'
    base.touch()
    build.assembly(value, base, work/'image', version='0.1.0', sequence=1)
    overlay = work/'image/mkosi.extra'
    # Install the actual assembled observer, host reader, policy, and units.
    for name in ('usr/lib/lanrith', 'usr/share/lanrith/router-metrics.json', 'etc/chrony/chrony.conf',
                 'etc/lanrith/services.nft', 'etc/lanrith/chrony-resolv.conf', 'etc/nftables.conf',
                 'usr/lib/systemd/system/lanrith-ntp-health.service', 'usr/lib/systemd/system/lanrith-ntp-health.timer',
                 'usr/lib/systemd/system/lanrith-router-metrics.service', 'usr/lib/systemd/system/lanrith-router-metrics.timer',
                 'etc/systemd/system/chrony.service.d/60-lanrith-services.conf'):
        dest = Path('/')/name
        if (overlay/name).is_dir():
            shutil.copytree(overlay/name, dest, dirs_exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(overlay/name, dest)
    for name in ('10-lanrith-firewall.conf', '30-lanrith-hardening.conf'):
        dest = 'etc/systemd/system/chrony.service.d/'+name
        write('/'+dest, (ROOT/'mkosi/base/mkosi.extra'/dest).read_text())
    libs = '/usr/lib/x86_64-linux-gnu'
    write('/etc/systemd/system/chrony.service.d/90-fixture.conf', '[Service]\nExecStart=\n'
          'ExecStart=/usr/sbin/chronyd -n -x -U -F 1 -u _chrony -f /etc/chrony/chrony.conf\n'
          'CapabilityBoundingSet=\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n'
          'AmbientCapabilities=\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'
          f'BindReadOnlyPaths={platform}{libs}:{libs}\n')
    for name in ('nftables', 'lanrith-services'):
        write('/etc/systemd/system/'+name+'.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    run('systemd-sysusers', overlay/'usr/lib/sysusers.d/80-lanrith-metrics.conf')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'nftables', 'lanrith-services')
    run('nft', '-f', '/etc/nftables.conf')
    plane = json.loads((overlay/'usr/share/lanrith/service-plane.json').read_text())
    service_runtime.start(plane)
    textfile = Path('/var/lib/node_exporter/textfile_collector/lanrith_router.prom')
    textfile.parent.mkdir(parents=True, exist_ok=True)

    def observe():
        run('systemctl', 'start', 'lanrith-ntp-health.service')
        return ntp_health_runtime.read_observation()

    def collect():
        run('systemctl', '--job-mode=ignore-dependencies', 'start', 'lanrith-router-metrics.service')
        return textfile.read_text()

    # Run the ordinary client under an unprivileged account in the admitted namespace.
    shutil.copytree(ROOT/'lanrith', work/'lanrith', ignore=shutil.ignore_patterns('__pycache__'))
    entry = work/'scripts/qualify-ntp-client.py'
    write(entry, (ROOT/'scripts'/entry.name).read_text())
    for path in (work/'lanrith').rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (work/'lanrith').chmod(0o755)
    def clients(expected):
        result = run('ip', 'netns', 'exec', 'lan', *role('nobody'), '/usr/bin/python3',
                     entry, '--profile', profile, '--network', 'home', check=False)
        assert result.returncode == int(not expected), (result.returncode, result.stderr, result.stdout)
        receipt = json.loads(result.stdout)
        assert receipt['result'] == ('pass' if expected else 'fail'), receipt
        assert {row['family'] for row in receipt['measurements']} == {4, 6}, receipt
        assert all(row['accepted'] == expected for row in receipt['measurements']), receipt
        print('client', receipt, flush=True)
    peer = subprocess.Popen(['ip', 'netns', 'exec', 'wan', '/usr/sbin/chronyd', '-n', '-x',
                             'local stratum 3', 'bindaddress '+WAN4, 'allow 198.51.100.0/24',
                             'pidfile /', 'bindcmdaddress /', 'cmdport 0'])
    try:
        run('systemctl', 'start', 'chrony')
        wait(lambda: selected() == [WAN4], 35)
        if timers:
            timer_outages(platform)
            return
        # Accelerate only the private peer's polling for the short holdover test.
        ctl('minpoll', WAN4, '0')
        ctl('maxpoll', WAN4, '0')
        ctl('burst', '4/4', WAN4)
        wait(lambda: float(ctl('tracking').split(',')[9]) < 10000, 50)
        initial = observe()
        assert initial['query_success'] and initial['synchronised'] and initial['clock_error_bound_seconds'] >= 0
        metrics = collect()
        assert 'lanrith_router_chrony_reference_timestamp_seconds '+str(initial['reference_timestamp_seconds'])+'\n' in metrics
        assert 'lanrith_router_chrony_clock_error_bound_seconds '+str(initial['clock_error_bound_seconds'])+'\n' in metrics
        clients(True)
        def block(namespace):
            run('ip', 'netns', 'exec', namespace, 'nft', 'add', 'table', 'inet', 'ntp_fixture')
            run('ip', 'netns', 'exec', namespace, 'nft', 'add', 'chain', 'inet', 'ntp_fixture', 'input',
                '{ type filter hook input priority -20; policy accept; }')
            run('ip', 'netns', 'exec', namespace, 'nft', 'add', 'rule', 'inet', 'ntp_fixture', 'input',
                'udp', 'sport' if namespace == 'lan' else 'dport', '123', 'drop')
        def restore(namespace):
            run('ip', 'netns', 'exec', namespace, 'nft', 'delete', 'table', 'inet', 'ntp_fixture')
        block('lan')
        clients(False)
        still = observe()
        assert still['query_success'] and still['synchronised']
        restore('lan')
        clients(True)

        block('wan')
        time.sleep(1)
        start = observe()
        dispersion = float(ctl('tracking').split(',')[11])
        time.sleep(5)
        held = observe()
        assert start['synchronised'] and held['synchronised'] and held['query_success']
        assert start['reference_timestamp_seconds'] == held['reference_timestamp_seconds']
        # Dispersion increases during holdover. The remaining correction can
        # change in either direction, so compare the total bound to the site's
        # objective rather than requiring it to increase on every query.
        assert float(ctl('tracking').split(',')[11]) > dispersion
        assert held['observed_timestamp_seconds'] > start['observed_timestamp_seconds']
        assert held['clock_error_bound_seconds'] >= 0 and start['clock_error_bound_seconds'] >= 0
        restore('wan')
        wait(lambda: float(ctl('tracking').split(',')[3]) > held['reference_timestamp_seconds'])
        fresh = observe()
        assert fresh['reference_timestamp_seconds'] > held['reference_timestamp_seconds']
        print('holdover and recovery', json.dumps([start, held, fresh]), flush=True)
        run('systemctl', 'stop', 'chrony')
        failed = observe()
        assert not failed['query_success'] and failed['reference_timestamp_seconds'] is None
        metrics = collect()
        assert 'lanrith_router_metrics_query_success{collector="chrony"} 0\n' in metrics
        assert 'lanrith_router_chrony_clock_error_bound_seconds' not in metrics
        run('systemctl', 'start', 'chrony')
        wait(lambda: selected() == [WAN4], 35)
        assert observe()['synchronised']
        assert 'lanrith_router_metrics_query_success{collector="chrony"} 1\n' in collect()
        print('observer, client and upstream recovered', flush=True)
    finally:
        peer.terminate()
        peer.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timers', action='store_true')
    qualify(timers=parser.parse_args().timers)
