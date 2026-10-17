#!/bin/sh
# Read-only predicates used by bounded boot-readiness retries. Return errors
# explicitly: an if/while caller disables shell errexit inside these functions.

# The network-base service starts one deadline before it performs any checks.
# Child verifiers inherit it, so a nested VPP readiness retry cannot restart a
# fresh acceptance window.  Direct diagnostic invocation gets the same bounded
# default rather than an unbounded wait.
router_boot_now() {
  # /proc/uptime is monotonic across NTP correction and is available before
  # network time can adjust CLOCK_REALTIME during early boot.
  awk 'NR == 1 { print int($1); exit }' /proc/uptime
}

router_boot_deadline_start() {
  if [ -n "${LANRITH_BOOT_DEADLINE_EPOCH:-}" ]; then
    case "$LANRITH_BOOT_DEADLINE_EPOCH" in
      *[!0-9]*|'')
        echo 'Router boot deadline is not a positive integer epoch.' >&2
        return 64
        ;;
    esac
    return 0
  fi

  timeout_seconds=${LANRITH_BOOT_TIMEOUT_SECONDS:-120}
  case "$timeout_seconds" in
    *[!0-9]*|''|0)
      echo 'Router boot timeout must be a positive integer number of seconds.' >&2
      return 64
      ;;
  esac
  now=$(router_boot_now) || {
    echo 'Router boot deadline cannot read the monotonic clock boundary.' >&2
    return 1
  }
  case "$now" in
    *[!0-9]*|'')
      echo 'Router boot deadline received an invalid monotonic-clock value.' >&2
      return 1
      ;;
  esac
  LANRITH_BOOT_DEADLINE_EPOCH=$((now + timeout_seconds))
  export LANRITH_BOOT_DEADLINE_EPOCH
}

router_boot_seconds_remaining() {
  router_boot_deadline_start || return $?
  now=$(router_boot_now) || return 1
  case "$now" in
    *[!0-9]*|'') return 1 ;;
  esac
  remaining=$((LANRITH_BOOT_DEADLINE_EPOCH - now))
  [ "$remaining" -gt 0 ] || return 1
  printf '%s\n' "$remaining"
}

router_wait_for() {
  [ "$#" -gt 0 ] || return 64
  router_boot_deadline_start || return $?
  while :; do
    "$@" && return 0
    status=$?
    # Usage and malformed-output errors cannot become healthy through a retry.
    case "$status" in
      64|65|66|124)
        echo "Router local readiness check failed without retry ($status): $*" >&2
        return "$status"
        ;;
    esac
    router_boot_seconds_remaining >/dev/null || {
      echo "Router local readiness deadline expired: $*" >&2
      return 75
    }
    sleep 1
  done
}

vppctl_bounded() {
  [ "$#" -gt 0 ] || return 64
  router_boot_deadline_start || return $?
  maximum_seconds=${LANRITH_VPPCTL_MAX_SECONDS:-5}
  case "$maximum_seconds" in
    *[!0-9]*|''|0) return 64 ;;
  esac
  remaining=$(router_boot_seconds_remaining) || {
    echo 'Router VPP CLI was not started because the local readiness deadline expired.' >&2
    return 124
  }
  if [ "$remaining" -lt "$maximum_seconds" ]; then
    maximum_seconds=$remaining
  fi
  # --foreground keeps the CLI in the service cgroup.  timeout sends TERM,
  # then KILL one second later, so an uncooperative VPP CLI cannot outlive the
  # systemd cleanup allowance or leave a background child after acceptance.
  timeout --foreground --kill-after=1s "${maximum_seconds}s" vppctl "$@"
}

require_wan_upload_shaping() {
  [ "$#" -eq 2 ] || return 64
  python3 - "$1" "$2" <<'PY'
import json
import subprocess
import sys

try:
    rate = int(sys.argv[2]) * 1000000 // 8
    queues = json.loads(subprocess.check_output(
        ['tc', '-j', 'qdisc', 'show', 'dev', sys.argv[1]], timeout=5))
    roots = [queue for queue in queues if queue.get('root') is True]
    if len(roots) != 1 or roots[0]['kind'] != 'cake':
        raise ValueError('missing single root CAKE queue')
    options = roots[0]['options']
    expected = {'bandwidth': rate, 'diffserv': 'besteffort', 'flowmode': 'dual-srchost',
                'nat': True, 'split_gso': True, 'ingress': False, 'overhead': 0, 'raw': False}
    if any(type(options.get(key)) is not type(value) or options[key] != value
           for key, value in expected.items()):
        raise ValueError('upload queue differs from signed policy')
except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
    print(f'WAN upload shaping: {error}', file=sys.stderr)
    raise SystemExit(1)
PY
}

require_translation_tun() {
  [ "$#" -eq 1 ] || return 64
  # Netlink follows the caller's network namespace; tuntap's sysfs view can
  # still belong to its parent after unshare, including in qualification.
  python3 - "$1" <<'PY'
import json
import subprocess
import sys

try:
    links = json.loads(subprocess.check_output(['ip', '-d', '-j', 'link', 'show', 'dev', sys.argv[1]], timeout=5))
    if len(links) != 1 or links[0]['ifname'] != sys.argv[1]:
        raise ValueError('unexpected interface')
    info = links[0]['linkinfo']
    if info['info_kind'] != 'tun' or info['info_data']['type'] != 'tun' or not info['info_data']['persist']:
        raise ValueError('expected a persistent TUN')
except (ValueError, KeyError, OSError, subprocess.SubprocessError):
    raise SystemExit(1)
PY
}

require_translation_pool() {
  [ "$#" -eq 3 ] || return 64
  python3 - "$1" "$2" "$3" <<'PY'
import ipaddress
import json
import subprocess
import sys

try:
    pool = ipaddress.IPv4Network(sys.argv[1])
    endpoint = ipaddress.IPv4Interface(sys.argv[2])
    interface = sys.argv[3]
    if endpoint.network.prefixlen != 32 or endpoint.ip not in pool:
        raise ValueError('translation endpoint must be a /32 inside its pool')
    def inspect(*arguments):
        return json.loads(subprocess.check_output(['ip', '-4', '-j', *arguments], timeout=5))
    addresses = inspect('address', 'show', 'dev', interface)
    if len(addresses) != 1 or {(entry['local'], entry['prefixlen']) for entry in addresses[0]['addr_info']} != {(str(endpoint.ip), 32)}:
        raise ValueError('unexpected IPv4 address or prefix length on translation TUN')
    found = False
    for route in inspect('route', 'show', 'table', 'all'):
        if route.get('dst', 'default') == 'default':
            continue
        prefix = ipaddress.IPv4Network(route['dst'])
        if not prefix.subnet_of(pool):
            continue
        kind = route.get('type', 'unicast')
        if kind == 'local' and prefix == endpoint.network and route.get('dev') == interface:
            continue
        if (kind != 'unicast' or route.get('dev') != interface or
                any(key in route for key in ('gateway', 'nexthops', 'multipath'))):
            raise ValueError(f'{prefix} diverts part of the translation pool')
        if prefix == pool and route.get('table', 'main') in ('main', 254):
            found = True
    if not found:
        raise ValueError('missing explicit translation pool route in main table')
except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
    print(f'translation routing: {error}', file=sys.stderr)
    raise SystemExit(1)
PY
}

require_ipv6_internal_route() {
  [ "$#" -eq 3 ] || return 64
  case "$2" in unicast|unreachable) ;; *) return 64 ;; esac
  routes=$(ip -6 route show table main exact "$1") || return 1
  printf '%s\n' "$routes" | awk -v prefix="$1" -v kind="$2" -v interface="$3" '
    NF {
      rows++
      first = 1
      if ($1 == "unreachable") first = 2
      if ((first == 2) != (kind == "unreachable") || $first != prefix) invalid = 1
      for (i = first + 1; i <= NF; i++) {
        if ($i == "via" || $i == "nhid" || $i == "nexthop") invalid = 1
        if ($i == "dev") device = $(i + 1)
      }
    }
    END { exit !(rows == 1 && !invalid && (kind == "unreachable" || device == interface)) }
  '
}

require_link_up() {
  link=$(ip -o link show dev "$1") || return 1
  printf '%s\n' "$link" | awk -F'[<>]' -v expected="$1" '
    NF { rows++ }
    /^[0-9]+: / {
      name = $1
      sub(/^[0-9]+: /, "", name)
      sub(/(@[^:]+)?:[[:space:]]*$/, "", name)
      if (name != expected) next
      found++
      if (NF != 3) invalid = 1
      count = split($2, flags, ",")
      for (item = 1; item <= count; item++) if (flags[item] == "UP") up++
    }
    END { exit !(rows == 1 && found == 1 && up == 1 && !invalid) }
  '
}

require_vpp_interface_state() {
  [ "$#" -eq 3 ] || return 64
  case "$3" in up|down) ;; *) return 64 ;; esac
  test -S "$1" || return 75
  interface_table=$(vppctl_bounded -s "$1" show interface "$2") || {
    status=$?
    case "$status" in
      124) return 124 ;;
      *) return 75 ;;
    esac
  }
  # VPP emits CRLF records even when vppctl is launched without a terminal.
  # Strip the carriage return before validating fields so the route/interface
  # predicates behave identically in systemd and interactive diagnostics.
  printf '%s\n' "$interface_table" | tr -d '\r' | awk -v expected="$2" -v state="$3" '
    $1 == expected {
      found++
      if (NF < 4 || $2 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+(\/[0-9]+)*$/) invalid = 1
      else if ($3 != state) retry = 1
    }
    END {
      if (invalid || found > 1) exit 65
      if (found == 0 || retry) exit 75
      exit 0
    }
  '
}

require_vpp_drop_default() {
  case "$2" in
    4) fib=ip; prefix=0.0.0.0/0; allow_absent=0 ;;
    6) fib=ip6; prefix=::/0; allow_absent=1 ;;
    *) return 64 ;;
  esac
  fib_table=$(vppctl_bounded -s "$1" show "$fib" fib) || {
    status=$?
    case "$status" in
      124) return 124 ;;
      *) return 75 ;;
    esac
  }
  # Select a complete route record, never a fixed number of following lines:
  # a later service route may legitimately forward. The only accepted default
  # leaves are drops (possibly behind a load-balance DPO). An unused IPv6 FIB
  # may omit the default, but an inspection error is never proof of absence.
  # VPP emits CRLF records even when vppctl is launched without a terminal.
  # Normalize those records before matching the route prefix and terminal DPO.
  printf '%s\n' "$fib_table" | tr -d '\r' | awk -v prefix="$prefix" -v allow_absent="$allow_absent" '
    NF { nonempty = 1 }
    /^ipv[46]-VRF:/ { table = 1; in_default = 0; next }
    $1 ~ /^[0-9a-fA-F:.]+\/[0-9]+$/ {
      in_default = ($1 == prefix)
      if (in_default) found++
      next
    }
    in_default && NF {
      if ($0 ~ /\]: dpo-drop ip[46][[:space:]]*$/) drop = 1
      else if ($0 !~ /\]: dpo-load-balance:/ && $1 !~ /^unicast-ip[46]-chain$/) invalid = 1
    }
    END {
      if (invalid || found > 1) exit 65
      if (!found) exit (allow_absent && (!nonempty || table) ? 0 : 75)
      exit (drop ? 0 : 65)
    }
  '
}

require_dynamic_ipv4_address() {
  # The retained DHCP WAN profile explicitly supports /24. Compare octets
  # numerically instead of interpolating addresses into a regular expression.
  addresses=$(ip -4 -o address show dev "$1" scope global) || return 1
  printf '%s\n' "$addresses" | awk -v network="$2" '
    BEGIN {
      if (split(network, subnet, /[./]/) != 5 || subnet[5] != "24" || subnet[4] != "0") invalid = 1
      for (i = 1; i <= 4; i++)
        if (subnet[i] !~ /^[0-9]+$/ || subnet[i] + 0 > 255) invalid = 1
    }
    $3 == "inet" && / scope global( |$)/ && !/ (tentative|dadfailed)( |$)/ {
      if (split($4, address, /[./]/) != 5 || address[5] != "24") next
      valid = 1
      for (i = 1; i <= 4; i++)
        if (address[i] !~ /^[0-9]+$/ || address[i] + 0 > 255) valid = 0
      for (i = 1; i <= 3; i++) if (address[i] + 0 != subnet[i] + 0) valid = 0
      if (valid && address[4] + 0 > 0 && address[4] + 0 < 255) found = 1
    }
    END { exit (invalid || !found) }
  '
}
