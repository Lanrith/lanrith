# Fan control

Lanrith includes a controller for the Linux hwmon temperature and PWM interfaces.
Enable it with `hardware.fancontrol.enabled: true` and select your sensors and
fan outputs. Omitting the section, or setting only `enabled: false`, leaves
firmware fan control in place and creates no service or thermal boot requirement.
See the commented [synthetic example](../examples/fancontrol.yaml).

The implementation has no board, CPU-vendor or NIC-driver table. It uses the
[kernel hwmon ABI](https://docs.kernel.org/hwmon/sysfs-interface.html). This
requires kernel drivers that expose temperature readings in millidegrees Celsius
and standard PWM duty values from 0 to 255, with 255 meaning full speed. IPMI/BMC
controllers, inverted PWM, voltage-valued thermistor channels and proprietary NIC
temperature interfaces need separate adapters; they are not inferred or probed.

## Select devices

Run `/usr/lib/lanrith/fancontrol-runtime inspect` on a compatible Lanrith image.
This unprivileged, read-only command lists chip names, stable device paths,
temperature inputs and labels, PWM outputs and fan tachometers. It never changes
fan speed or reads owner YAML. Confirm fan wiring and safe running duty using
the hardware documentation before enabling control. Lanrith does not run
`sensors-detect` or `pwmconfig`, sweep fan speeds, or stop a fan for calibration.

Each named temperature source selects either:

- `hwmon: {name: <chip name>}`, optionally with `device: <path relative to
  /sys/devices>`. Multiple matching chips are allowed for temperature sources,
  for example multiple CPU packages.
- `interface: <key in hardware.interfaces>`. The compiler resolves the Linux
  interface name; the runtime reads only hwmon devices attached to that NIC's
  kernel device. It supports NICs from any vendor that expose this interface.

Use `inputs: all` (the default) for all `tempN_input` channels on the selected
devices, or an explicit list such as `[temp1_input, temp2_input]`. All configured
sources are required. A missing NIC sensor is a fault, rather than permission to
ignore the NIC. A VPP-owned interface cannot supply kernel hwmon telemetry through
an interface selector. Unsupported or driver-detached NICs require another
supported sensor source before enabling this feature.

Fan mappings use a chip name and optional stable device path, plus a `pwmN`
output. Each mapping must resolve to one device, and two mappings cannot control
the same physical output. `hwmonN` enumeration numbers are never accepted as
stable device selectors. Changing their order across boots does not change the
selected device. Each fan names the temperature sources that should affect it.
Separate fans may share sources or follow different subsets.

## Cooling policy

Every source has `minimum_c` and `maximum_c` thresholds. A fan runs at its
`minimum_pwm` below the first threshold, increases linearly to 255 between them,
and runs at 255 at or above the second. CPU and NIC thresholds can differ. The
highest cooling demand across a fan's sources wins; readings are never averaged
in a way that hides a hot component. The hottest selected channel determines
each source's reading.

`minimum_pwm` defaults to 128 and accepts 1–254. Fans are never deliberately
stopped. Set a duty that reliably keeps the actual fan running. An optional
`tachometer: fanN_input` enables stall detection, with `minimum_rpm` defaulting to
1. Without a tachometer, the controller cannot detect mechanical failure.

`hysteresis_c` defaults to 3 (0–20). Rising temperature increases cooling
immediately; a lower reading must fall by at least this amount before cooling
is reduced. `interval_seconds` defaults to 5 (1–10). At startup all selected fans
run at full speed for `startup_seconds`, default 3 (1–30), before normal control
and tachometer checks begin. The controller leaves polarity, PWM frequency and
firmware trip points unchanged. It selects manual mode 1 when `pwmN_enable` is
available; drivers with other mode semantics are unsupported.

## Fault handling and privileges

Missing or unreadable temperatures, invalid readings, hardware fault/critical
alarm flags, stalled tachometers and rejected PWM writes fail the service and
request full speed on every output that can still be written. Clean shutdown
also leaves fans at full speed. The service manager retries failures and runs a
separate full-speed action after exit, including a crash or watchdog timeout.
It never restores a previous low duty during shutdown. A missing or ambiguous
fan controller is not guessed; other resolvable outputs still receive full speed.

An enabled controller is a required boot-health unit. Its `Type=notify` readiness
follows a successful temperature/control cycle after the startup interval; a
30-second systemd watchdog supervises subsequent cycles. Failed cooling checks
prevent candidate acceptance. These controls cannot guarantee cooling after a
kernel hang, power failure, disconnected fan or failed controller. Hardware
thermal protection remains necessary, and full-speed behavior must be checked
on each supported physical profile.

The root bootstrap validates a root-owned compiled manifest and opens only the
selected PWM and mode attributes. Before the loop, it discards supplementary
groups, all root user/group IDs and active capabilities, becoming the dedicated
non-login `lanrith-fancontrol` account. Only the open PWM descriptors retain write
authority. The service has no network listener, uses an AF_UNIX-only sandbox for
systemd notifications, and has memory, task and descriptor limits. Its bootstrap
has only SETUID/SETGID capabilities; kernel, mount and reboot operations are
blocked. Read/write access to `/sys/devices` allows that bounded bootstrap to
open hardware attributes; ordinary file permissions deny new privileged opens
after the UID change. No credential or persistent control state is needed.

Owner YAML is a build input only. The compiler emits a narrow, strict JSON
thermal contract and native service/account files; source YAML, normalized
configuration and compiler modules are absent from the image. Changing mappings
or thresholds requires a newly built signed image. Existing host metrics already
collect hwmon values when metrics are enabled; fan control does not enable a
metrics listener or depend on monitoring, DNS, directory policy or translation.

## Verification

`tests/test_fancontrol.py` uses synthetic hwmon devices to exercise CPU/NIC
selection, maximum demand, hysteresis, missing/faulted sensors, stalls, startup
and shutdown fallback, stable selectors, ambiguity, path rejection and ordinary
user denial. Assembly tests cover both administration modes, required service
activation and execution without YAML or compiler modules.

For every physical profile that enables this feature, retain candidate-bound
evidence of actual wiring, driver loading, readable CPU/NIC sensors, full-speed
PWM read-back and RPM, the calibrated minimum running duty, heating and cooling,
and sensor loss. Inspect the live process's dedicated UID, empty supplementary
groups/capabilities, seccomp, resource ceilings and ordinary-user write denials.
Exercise service termination, SIGKILL and watchdog failure; verify full-speed
fallback and failed boot acceptance. Repeat boot, update and rollback with the
selected build-time mappings. Source tests do not establish physical fan safety.
