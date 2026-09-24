# DLINK-DIR-825M-V009-MEM: Authenticated stack buffer overflow in debug diagnostics

**Product:** D-Link DIR-825M Hardware A1
**Firmware:** 1.1.8.6 (current firmware listed by D-Link Latin America)
**CWE:** CWE-121
**CVSS:** 4.9 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H)
**Authentication:** Administrator authentication is required.
**Affected entry:** POST /boafrm/formDebugDiagnosticRun, parameter host

A long host value overflows a fixed-size stack buffer and aborts the boa Web process, causing a process-level denial of service.

The unbounded sprintf() writes the attacker-controlled host value and a fixed suffix into a 260-byte stack buffer.

## Shared emulation

Use the shared model environment: [dir-825m emulator](../../../emu/dir-825m/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. Start the documented callback listener if this is a command-injection case, then run:

```sh
python3 poc.py --target http://192.168.224.1 --username admin --password admin --length 500
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause

See [`root_cause.c`](root_cause.c) for the case-specific pseudocode excerpt.

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

