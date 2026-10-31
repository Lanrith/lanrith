"""Compile bounded journal redaction and authenticated OTLP delivery."""

import ipaddress as ip
import json
from urllib.parse import urlsplit

from . import bindings, intent, service_plane
from .release import canonical


def active(value):
    return value.get('observability', {}).get('logs', {}).get('enabled', False)


def manifest(value):
    settings = value['observability']['logs']
    target = ip.ip_address(urlsplit(settings['endpoint']).hostname)
    source = next(address for address in intent.service_addresses(value, 'logs')
                  if ip.ip_address(address).version == target.version)
    return {
        'schema_version': 1,
        'endpoint': settings['endpoint'],
        'target': str(target),
        'source': source,
        'tls_server_name': settings['tls_server_name'],
        'username': settings['username'],
        'credential_name': settings['credential'],
    }


def configuration(value):
    policy = manifest(value)
    quote = json.dumps
    return '''// Generated from admitted intent. No source configuration or secret is read at runtime.
// Journal bodies never become labels, and redaction runs before the persistent queue.
loki.relabel "router_journal" {
  forward_to = []
  rule {
    source_labels = ["__journal__systemd_unit"]
    regex         = "alloy\\\\.service"
    action        = "drop"
  }
  rule {
    source_labels = ["__journal__systemd_unit"]
    target_label  = "unit"
    regex         = "([A-Za-z0-9_.@:-]{1,128})"
  }
  rule {
    source_labels = ["__journal_priority"]
    target_label  = "priority"
    regex         = "([0-7])"
  }
  rule {
    action = "labelkeep"
    regex  = "^(host|job|unit|priority)$"
  }
}

loki.source.journal "router" {
  path           = "/var/log/journal"
  max_age        = "6h"
  format_as_json = true
  labels         = { host = HOSTNAME, job = "router-journal" }
  relabel_rules  = loki.relabel.router_journal.rules
  forward_to     = [loki.process.router_redaction.receiver]
}

loki.process "router_redaction" {
  forward_to = [otelcol.receiver.loki.router.receiver]
  stage.json {
    expressions = { message = "MESSAGE", journal_boot = "_BOOT_ID", journal_time = "__REALTIME_TIMESTAMP", journal_transport = "_TRANSPORT" }
  }
  stage.structured_metadata {
    values = { journal_boot = "journal_boot", journal_time = "journal_time", journal_transport = "journal_transport" }
  }
  stage.output { source = "message" }
  stage.drop {
    expression          = "-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
    drop_counter_reason = "private_key_material"
  }
  stage.replace {
    expression = "(?i)\\\\b(?:proxy-)?authorization[\\\"\\\\x27]?\\\\s*[:=]\\\\s*(.+)"
    replace    = "[REDACTED]"
  }
  stage.replace {
    expression = "(?i)\\\\b[a-z][a-z0-9+.-]*://([^/@\\\\s]+)@"
    replace    = "[REDACTED]"
  }
  stage.replace {
    expression = "(?i)\\\\b(?:Bearer|Basic)\\\\s+([A-Za-z0-9._~+/-]+=*)"
    replace    = "[REDACTED]"
  }
  stage.replace {
    expression = "(?i)\\\\b(?:password|passwd|passphrase|secret|(?:access[_-]?|refresh[_-]?|id[_-]?|api[_-]?)?token|api[_-]?key|authpass|privpass|cryptopass|community)[\\\"\\\\x27]?\\\\s*[:=]\\\\s*(\\\"(?:[^\\\"\\\\\\\\]|\\\\\\\\.)*\\\"|\\\\x27(?:[^\\\\x27\\\\\\\\]|\\\\\\\\.)*\\\\x27|[^\\\\s,;&}\\\\]]+)"
    replace    = "[REDACTED]"
  }
  stage.replace {
    expression = "(?i)--(?:password|passwd|passphrase|secret|(?:access[_-]?|refresh[_-]?|id[_-]?|api[_-]?)?token|api[_-]?key|authpass|privpass|cryptopass|community)\\\\s+(\\\"(?:[^\\\"\\\\\\\\]|\\\\\\\\.)*\\\"|\\\\x27(?:[^\\\\x27\\\\\\\\]|\\\\\\\\.)*\\\\x27|[^\\\\s,;&}\\\\]]+)"
    replace    = "[REDACTED]"
  }
  stage.replace {
    expression = "(?:^|\\\\s)-(?:A|X)\\\\s+(\\\"(?:[^\\\"\\\\\\\\]|\\\\\\\\.)*\\\"|\\\\x27(?:[^\\\\x27\\\\\\\\]|\\\\\\\\.)*\\\\x27|[^\\\\s,;&}\\\\]]+)"
    replace    = "[REDACTED]"
  }
}

otelcol.receiver.loki "router" {
  output { logs = [otelcol.processor.groupbyattrs.router.input] }
}

otelcol.processor.groupbyattrs "router" {
  keys = ["host", "job", "unit", "priority"]
  output { logs = [otelcol.exporter.otlphttp.router.input] }
}

otelcol.storage.file "router" {
  directory             = "/var/lib/lanrith-alloy/queue"
  directory_permissions = "0700"
  fsync                  = true
  compaction {
    on_start                      = true
    on_rebound                    = true
    rebound_needed_threshold_mib = 32
    rebound_trigger_threshold_mib = 8
  }
}

local.file "router_password" {
  filename  = "/run/lanrith-logs/password"
  is_secret = true
}

otelcol.auth.basic "router" {
  username = USERNAME
  password = local.file.router_password.content
}

otelcol.exporter.otlphttp "router" {
  client {
    endpoint = ENDPOINT
    auth     = otelcol.auth.basic.router.handler
    timeout  = "15s"
    tls {
      server_name = SERVER_NAME
      min_version = "1.2"
    }
  }
  retry_on_failure {
    initial_interval = "1s"
    max_interval     = "30s"
    max_elapsed_time = "0s"
  }
  sending_queue {
    storage           = otelcol.storage.file.router.handler
    sizer             = "bytes"
    queue_size        = 67108864
    num_consumers     = 1
    block_on_overflow = false
    batch {
      sizer         = "bytes"
      min_size      = 65536
      max_size      = 524288
      flush_timeout = "1s"
    }
  }
}
'''.replace('HOSTNAME', quote(value['hostname'])).replace(
        'USERNAME', quote(policy['username'])).replace(
        'ENDPOINT', quote(policy['endpoint'])).replace(
        'SERVER_NAME', quote(policy['tls_server_name']))


def render(value):
    if not active(value):
        return {}
    policy = manifest(value)
    # Resolving the target to exactly one declared attachment is both a
    # validation gate and the source of the firewall's outgoing interface.
    service_plane.destination_network(value, ip.ip_address(policy['target']))
    credential = policy['credential_name']
    unit = (
        '[Unit]\nDescription=Redact and export the router journal\n'
        'Requires=lanrith-services.service\nAfter=lanrith-services.service systemd-journald.service\n'
        'BindsTo=lanrith-services.service nftables.service\n\n[Service]\nType=notify\nNotifyAccess=main\n'
        'User=alloy\nGroup=alloy\nSupplementaryGroups=systemd-journal\n'
        'NetworkNamespacePath=/run/netns/'+service_plane.NAMESPACE+'\n'
        'LoadCredential='+credential+':'+bindings.credential_path(value, credential)+'\n'
        'ExecStartPre=+/usr/lib/lanrith/logs-runtime stage\n'
        'ExecStart=\nExecStart=/usr/lib/lanrith/logs-runtime run\nExecReload=\n'
        'EnvironmentFile=\nWorkingDirectory=/var/lib/lanrith-alloy\n'
        'TimeoutStartSec=35s\nTimeoutStopSec=20s\nWatchdogSec=30s\n'
        'StateDirectory=lanrith/alloy\nStateDirectoryMode=0750\n'
        'BindPaths=/var/lib/lanrith/alloy:/var/lib/lanrith-alloy\n'
        'RuntimeDirectory=lanrith-logs\nRuntimeDirectoryMode=0750\nUMask=0027\n'
        'ReadWritePaths=/var/lib/lanrith-alloy /run/lanrith-logs\n'
        'IPAddressDeny=any\nIPAddressAllow='+policy['target']+'\nIPAddressAllow=127.0.0.1/32\n'
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nNoNewPrivileges=yes\n'
        'PrivateTmp=yes\nPrivateDevices=yes\nProtectHome=yes\nProtectSystem=strict\n'
        'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
        'Environment=GOMEMLIMIT=128MiB\nMemoryMax=512M\nMemorySwapMax=0\nTasksMax=64\nLimitNOFILE=1024\n'
        'Restart=on-failure\nRestartSec=10s\n')
    return {
        'usr/share/lanrith/logs.json': canonical(policy).decode(),
        'etc/alloy/config.alloy': configuration(value),
        'etc/systemd/system/alloy.service.d/60-lanrith.conf': unit,
        'usr/lib/systemd/system/lanrith-telemetry-heartbeat.service': (
            '[Unit]\nDescription=Emit the remote telemetry liveness identity\n'
            'Requires=boot-complete.target alloy.service\nAfter=boot-complete.target alloy.service\n\n'
            '[Service]\nType=oneshot\nUser=alloy\nGroup=alloy\n'
            'ExecStart=/usr/bin/lanrith-runtime telemetry\n'
            'NoNewPrivileges=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectHome=yes\nProtectSystem=strict\n'
            'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
            'RestrictAddressFamilies=AF_UNIX\nMemoryDenyWriteExecute=yes\nLockPersonality=yes\n'
            'SystemCallArchitectures=native\nSystemCallFilter=@system-service\n'),
        'usr/lib/systemd/system/lanrith-telemetry-heartbeat.timer': (
            '[Unit]\nDescription=Emit a bounded router heartbeat every minute\n\n'
            '[Timer]\nOnBootSec=60s\nOnUnitActiveSec=60s\nAccuracySec=5s\nRandomizedDelaySec=5s\n'
            'Unit=lanrith-telemetry-heartbeat.service\n\n[Install]\nWantedBy=timers.target\n'),
    }
