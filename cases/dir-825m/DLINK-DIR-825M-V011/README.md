# DLINK-DIR-825M-V011: Authenticated command injection in WPS target SSID

**Product:** D-Link DIR-825M Hardware A1
**Firmware:** 1.1.8.6 (current firmware listed by D-Link Latin America)
**CWE:** CWE-78
**CVSS:** 7.2 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
**Authentication:** Administrator authentication is required.
**Affected entry:** POST /boafrm/formWsc, parameter targetAPSsid

An authenticated administrator can inject a command substitution into the WPS SSID value and execute arbitrary operating-system commands.

The handler escapes only a limited character set, places targetAPSsid inside a double-quoted iwpriv command, and calls system(); shell command substitution remains active.

## Shared emulation

Use the shared model environment: [dir-825m emulator](../../../emu/dir-825m/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. In a second terminal on the host, start this callback listener:

```sh
sudo python3 -m http.server 80 --bind 192.168.224.2
```

3. From this case directory, run:

```sh
python3 poc.py --target http://192.168.224.1 --username admin --password admin --callback 192.168.224.2
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause and attack path

The attack starts at authenticated `POST /boafrm/formWsc` with `targetAPSsid`. The handler accepts the value under a short length check, copies it into `v40`, applies a limited character transformation, and then places it inside a quoted `iwpriv ... wsc_specssid="%s"` command. The command is executed with `system()`.

The transformation does not disable shell command substitution inside the double-quoted command. A value containing `$(...)` therefore executes when the generated command is interpreted. The PoC uses this path to make the guest send a callback.

The relevant pseudocode is embedded below. It shows the request value being read, transformed or copied, and reaching the vulnerable sink.

```c
/* IDA pseudocode excerpt from DIR-825M firmware 1.1.8.6. */
 50600:   sub_42AEAC("wlan0");
 50601:   apmib_get(59, &v46);
 50602:   apmib_get(22, &v44);
 50603:   v53 = 4653056;
 50604:   sub_42AEAC("wlan1");
 50605:   apmib_get(59, &v45);
 50606:   apmib_get(22, &v43);
 50607:   sprintf(v41, "wlan%d", wlan_idx);
 50608:   sub_42AEAC(v41);
 50609:   wlan_idx = v2;
 50610:   memset(v42, 0, 30);
 50611:   v3 = (unsigned char *)sub_41351C(a1, (int)"targetAPMac", (int)"");
 50612:   v4 = (char *)sub_41351C(a1, (int)"targetAPSsid", (int)"");
 50613:   v5 = (char *)sub_41351C(a1, (int)"submit-url", (int)"");
 50614:   if ( *(unsigned char *)sub_41351C(a1, (int)"resetUnCfg", (int)"") == 49 )
 50615:   {

 50794:       v29 = v23 == 0;
 50795:       v30 = v46;
 50796:       if ( !v29 )
 50797:       {
 50798:         if ( (unsigned int)strlen(v4) < 0x21 )
 50799:         {
 50800:           memset(v40, 0, 128);
 50801:           strcpy(v40, v4);
 50802:           sub_42CDA0(v40);
 50803:           sprintf(v41, "iwpriv wlan%d set_mib wsc_specssid=\"%s\" ", wlan_idx, (const char *)v40);
 50804:           system(v41);
 50805:         }
```

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

