# DLINK-DIR-825M-V008: Authenticated command injection in LTE FOTA URL

**Product:** D-Link DIR-825M Hardware A1
**Firmware:** 1.1.8.6 (current firmware listed by D-Link Latin America)
**CWE:** CWE-78
**CVSS:** 7.2 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
**Authentication:** Administrator authentication is required.
**Affected entry:** POST /boafrm/formLtefotaUpgradeQuectel, parameter fota_url

An authenticated administrator can inject shell metacharacters and execute arbitrary operating-system commands with the Web service's privileges.

The handler accepts fota_url after checking only that it contains an allowed URL scheme, interpolates it into an upgrade_quectel shell command, and passes the result to system().

## Shared emulation

Use the shared model environment: [dir-825m emulator](../../../emu/dir-825m/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. In a second terminal on the host, start this callback listener:

```sh
python3 -m http.server 8000 --bind 192.168.224.2
```

3. From this case directory, run:

```sh
python3 poc.py --target http://192.168.224.1 --username admin --password admin --callback 192.168.224.2:8000
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause

See [`root_cause.c`](root_cause.c) for the case-specific pseudocode excerpt.

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

