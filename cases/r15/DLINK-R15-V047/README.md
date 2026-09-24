# DLINK-R15-V047: Unauthenticated NULL-pointer dereference in Authorization parsing

**Product:** D-Link R15 Hardware A1
**Firmware:** 1.22 (current official release)
**CWE:** CWE-476
**CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
**Authentication:** No authentication is required; the malformed header is parsed before authentication completes.
**Affected entry:** HTTP request with malformed Authorization: Basic header

A remote unauthenticated request dereferences NULL and terminates the httpd process, causing a process-level denial of service.

The parser assumes strchr(decoded_credentials, ':') succeeds and writes through the returned pointer without checking for NULL.

## Shared emulation

Use the shared model environment: [r15 emulator](../../../emu/r15/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. Start the documented callback listener if this is a command-injection case, then run:

```sh
python3 poc.py --target 192.168.229.1 --port 80
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause

See [`root_cause.c`](root_cause.c) for the case-specific pseudocode excerpt.

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

