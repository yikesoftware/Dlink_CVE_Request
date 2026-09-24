# DLINK-DIR-822K-TK-V005: WPS target SSID command injection

**Product:** D-Link DIR-822K/TK Telkom
**Firmware:** V1.00 Telkom, build 2025-06-24 (latest package in D-Link's directory; product is EOL)
**CWE:** CWE-78
**CVSS:** 7.2 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
**Authentication:** Administrator authentication is required.
**Affected entry:** POST /boafrm/formWsc, parameter targetAPSsid

An authenticated administrator can inject shell syntax and execute arbitrary operating-system commands with the Web service's privileges.

The targetAPSsid parameter is interpolated into a shell command without complete shell escaping and reaches system().

## Shared emulation

Use the shared model environment: [dir-822k-tk emulator](../../../emu/dir-822k-tk/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. In a second terminal on the host, start this callback listener:

```sh
sudo python3 -m http.server 80 --bind 192.168.223.2
```

3. From this case directory, run:

```sh
python3 poc.py --target http://192.168.223.1 --username admin --password admin --callback 192.168.223.2
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause

See [`root_cause.c`](root_cause.c) for the case-specific pseudocode excerpt.

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

