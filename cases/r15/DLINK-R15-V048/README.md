# DLINK-R15-V048: Unauthenticated stack overflow in Accept-Encoding quality parsing

**Product:** D-Link R15 Hardware A1
**Firmware:** 1.22 (current official release)
**CWE:** CWE-121
**CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
**Authentication:** No authentication is required. The firmware's native HTTP-compression option must be enabled.
**Affected entry:** HTTPS request with an overlong gzip quality value in Accept-Encoding

An unauthenticated attacker can overflow a stack buffer and crash httpd; the fault address contains attacker-controlled bytes.

The quality token is copied byte-by-byte into a 32-byte stack buffer without a length bound before strtof() parses it.

## Shared emulation

Use the shared model environment: [r15 emulator](../../../emu/r15/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. In the extracted emulator directory, run `python3 ./enable-v048.py` as described by the emulator README.
3. Start the documented listener if applicable, then run:

```sh
python3 poc.py --target 192.168.229.1 --port 443
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause

See [`root_cause.c`](root_cause.c) for the case-specific pseudocode excerpt.

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

