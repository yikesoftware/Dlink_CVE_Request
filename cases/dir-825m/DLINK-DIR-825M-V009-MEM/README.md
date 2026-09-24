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

## Root cause and attack path

The attack starts at authenticated `POST /boafrm/formDebugDiagnosticRun` with `host`. The handler stores the request value in the fixed 260-byte stack buffer `v7`, appends the fixed output-redirection suffix with `sprintf`, and then invokes `system()`.

`sprintf` has no destination-size argument. A sufficiently long `host` value therefore writes past `v7`, corrupts the `boa` Web process stack and produces the documented fatal signal. The PoC uses a 500-byte value and checks both the crash record and the temporary Web-service outage.

The relevant pseudocode is embedded below. It shows the request value being read, transformed or copied, and reaching the vulnerable sink.

```c
/* IDA pseudocode excerpt from DIR-825M firmware 1.1.8.6. */
 20361: //----- (0041CE08) --------------------------------------------------------
 20362: int   sub_41CE08(unsigned int *a1, int a2)
 20363: {
 20364:   const char *v4; // $v0
 20365:   const char *v5; // $s0
 20366:   int result; // $v0
 20367:   unsigned char v7[260]; // [sp+18h] [-104h] BYREF
 20368: 
 20369:   memset(v7, 0, 256);
 20370:   v4 = (const char *)sub_41351C(a1, (int)"host", (int)"");
 20371:   v5 = v4;
 20372:   if ( !v4 || *v4 )
 20373:   {
 20374:     result = strncmp(v4, "top", 3);
 20375:     if ( result )
 20376:     {
 20377:       result = strncmp(v5, "ping", 4);
 20378:       if ( result )
 20379:       {
 20380:         result = strcmp(v5, "flash all");
 20381:         if ( result )
 20382:         {
 20383:           unlink("/var/tmp/debugDiagnosticResult");
 20384:           sprintf(v7, "%s &> /var/tmp/debugDiagnosticResult", v5);
 20385:           system(v7);
 20386:           return 0;
```

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

