# DLINK-DIR-822K-TK-V003: Traceroute diagnostic host command injection

**Product:** D-Link DIR-822K/TK Telkom
**Firmware:** V1.00 Telkom, build 2025-06-24 (latest package in D-Link's directory; product is EOL)
**CWE:** CWE-78
**CVSS:** 7.2 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
**Authentication:** Administrator authentication is required.
**Affected entry:** POST /boafrm/formTracerouteDiagnosticRun, parameter host

An authenticated administrator can inject shell syntax and execute arbitrary operating-system commands with the Web service's privileges.

The host parameter is interpolated into a shell command without complete shell escaping and reaches system().

## Shared emulation

Use the shared model environment: [dir-822k-tk emulator](../../../emu/dir-822k-tk/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. In a second terminal on the host, start this callback listener:

```sh
python3 -m http.server 8000 --bind 192.168.223.2
```

3. From this case directory, run:

```sh
python3 poc.py --target http://192.168.223.1 --username admin --password admin --callback 192.168.223.2:8000
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause and attack path

The attack starts at the authenticated `POST /boafrm/formTracerouteDiagnosticRun` handler. The handler obtains the request-controlled `host` and `ipVer` values, places them into the `traceroute` command stored in `v7`, and calls `system()`.

There is no complete shell-safe argument construction between the HTTP parameter and the sink. Shell syntax in `host` is consequently interpreted by the service rather than passed as an opaque traceroute destination. The PoC uses a callback-only command so the effect is observable without opening an interactive shell.

The relevant pseudocode is embedded below. It shows the request value being read, transformed or copied, and reaching the vulnerable sink.

```c
/* IDA pseudocode excerpt; addresses are from the analyzed firmware. */
  18250: //----- (00419E00) --------------------------------------------------------
  18251: int   sub_419E00(unsigned int *a1, int a2)
  18252: {
  18253:   const char *v4; // $s0
  18254:   const char *v5; // $s1
  18255:   char v7[260]; // [sp+18h] [-104h] BYREF
  18256: 
  18257:   memset(v7, 0, 256);
  18258:   v4 = (const char *)sub_40F4CC(a1, (int)"host", (int)"");
  18259:   v5 = (const char *)sub_40F4CC(a1, (int)"ipVer", (int)"");
  18260:   if ( !v4 || *v4 )
  18261:   {
  18262:     unlink("/var/tmp/tracerouteDiagnosticResult");
  18263:     sprintf(v7, "traceroute -%s %s -w 2 -m 20 &> /var/tmp/tracerouteDiagnosticResult", v5, v4);
  18264:     fprintf(stderr, "%s\n", v7);
  18265:     system(v7);
  18266:     return 0;
  18267:   }
  18268:   else
  18269:   {
  18270:     strcpy(a2, "Host is Error!");
  18271:     return -1;
  18272:   }
  18273: }
  18274: // 480050: using guessed type int   unlink(unsigned int);
  18275: // 4800E0: using guessed type int fprintf(unsigned int, const char *, ...);
  18276: // 480290: using guessed type int   memset(unsigned int, unsigned int, unsigned int);
  18277: // 4803D0: using guessed type int   strcpy(unsigned int, unsigned int);
  18278: // 480420: using guessed type int   system(unsigned int);
  18279: // 4807A0: using guessed type int sprintf(unsigned int, const char *, ...);
  18280: // 493CFC: using guessed type int stderr;
  18281:
```

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

