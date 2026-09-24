# DLINK-DIR-BE3602-V045: Unauthenticated command injection in framed JSON DMZ handler

**Product:** D-Link DIR-BE3602
**Firmware:** 1.04, build 2025-07-21 (newer than public FOTA 1.02; no newer public package located)
**CWE:** CWE-78
**CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Authentication:** No authentication is required by the affected framed-JSON service.
**Affected entry:** TLS framed-JSON service, method setDmzInfo, field dmz

A network attacker can execute arbitrary operating-system commands with the service's privileges.

The dmz JSON value is concatenated into a shell command. A single quote terminates the intended quoted value and permits command injection before the command reaches system().

## Shared emulation

Use the shared model environment: [dir-be3602 emulator](../../../emu/dir-be3602/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. In a second terminal on the host, start this callback listener:

```sh
python3 -m http.server 8000 --bind 192.168.210.2
```

3. From this case directory, run:

```sh
python3 poc.py --target 192.168.210.1 --port 18169 --callback 192.168.210.2:8000
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause

See [`root_cause.c`](root_cause.c) for the case-specific pseudocode excerpt.

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

