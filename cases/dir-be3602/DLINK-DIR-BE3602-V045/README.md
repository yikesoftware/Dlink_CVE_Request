# DLINK-DIR-BE3602-V045: Unauthenticated command injection in framed JSON DMZ handler

**Product:** D-Link DIR-BE3602
**Firmware:** 1.04, build 2025-07-21 (newer than public FOTA 1.02; no newer public package located)
**CWE:** CWE-78
**CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Authentication:** No authentication is required by the affected framed-JSON service.
**Affected entry:** TLS framed-JSON service, method setDmzInfo, field dmz

A network attacker can execute arbitrary operating-system commands with the service's privileges.

The dmz JSON value is concatenated into a shell command. A single quote terminates the intended quoted value and permits command injection before the command reaches system().

## Shared emulation

Use the shared model environment: [dir-be3602 emulator](../../../emu/dir-be3602/README.md).
Start it exactly as described there, then return to this case directory.

## Reproduction

1. Start the shared emulator and wait for its documented readiness check.
2. In a second terminal on the host, start this callback listener:

```sh
python3 -m http.server 8000 --bind 192.168.210.2
```

3. From this case directory, run:

```sh
python3 poc.py --target 192.168.210.1 --port 18169 --callback 192.168.210.2:8000
```

Observe the callback or crash indicator described in the shared emulator README. The included `validation.log` records the internal self-test evidence.

## Root cause and attack path

The attack starts before authentication at the TLS framed-JSON service on port 18169. The service reads a framed JSON request, extracts the method and the method-specific `dmz` field with `jsonfilter`, and passes the resulting value to the handler table. The handler builds a shell command containing the DMZ value and executes it with `system()`.

The value is inserted inside a single-quoted shell fragment without escaping a single quote. The PoC closes that quote, adds a `wget` callback command, and restores the remaining syntax. Because the service accepts the request without a Web login, the callback demonstrates unauthenticated command execution.

The relevant pseudocode is embedded below. It shows the request value being read, transformed or copied, and reaching the vulnerable sink.

```c
/* IDA pseudocode excerpt; addresses are from the analyzed firmware. */
   1167:     v2 = -1;
   1168:     debug("web-api.c", 370, 1, "SSL_accept failed!");
   1169:   }
   1170:   else
   1171:   {
   1172:     v2 = -1;
   1173:     while ( 1 )
   1174:     {
   1175:       memset(v10, 0, sizeof(v10));
   1176:       do
   1177:         v5 = SSL_read(v4, v10, 4096);
   1178:       while ( v5 == -1 && *(unsigned int *)_errno_location(-1) == 4 );
   1179:       v10[0] = ntohl(v10[0]);
   1180:       v6 = ntohl(v10[1]);
   1181:       v10[1] = v6;
   1182:       if ( !v5 || v6 + 8 > v5 )
   1183:         break;
   1184:       v7 = v5 - 8;
   1185:       *off_14FD0 = v10[0];
   1186:       if ( v7 >= 4096 )
   1187:         v8 = 4096;
   1188:       else
   1189:         v8 = v7;
   1190:       if ( v11 < (char *)&v10[2] && &v10[2] < (unsigned int *)&v11[v8]
   1191:         || v11 > (char *)&v10[2] && v11 < (char *)&v10[2] + v8
   1192:         || v8 > 0xFF8 )
   1193:       {
   1194:         __und(0);
   1195:       }
   1196:       memcpy(v11, &v10[2], v8);
   1197:       v2 = sub_1DBC(v4, v9, v11, v7, 1);
   1198:       if ( v2 )
   1199:         break;
   1200:       usleep(50000);
   1201:     }
   1202:     usleep(50000);
   1203:     if ( !v2 )
   1204:       goto LABEL_26;
   1205:   }
   1206:   sub_1C58(v4, v9, "{\"errCode\":\"1\",\"result\":\"internal error\",\"seq\":\"\"}", 50, 1);
   1207: LABEL_26:
   1208:   SSL_free(v4);
   1209:   if ( v9 >= 0 )
   1210:     close();
   1211:   return v2;
   1212: }
   1213: // BE4: using guessed type int debug(unsigned int, unsigned int, unsigned int, const char *, ...);
   1214: // C08: using guessed type int   _errno_location(unsigned int);
   1215: // C20: using guessed type int   usleep(unsigned int);
   1216: // C2C: using guessed type int   memcpy(unsigned int, unsigned int, unsigned int);
   1217: // CA4: using guessed type int   SSL_set_fd(unsigned int, unsigned int);
   1218: // CE0: using guessed type int   SSL_new(unsigned int);
   1219: // CEC: using guessed type int   SSL_read(unsigned int, unsigned int, unsigned int);
   1220: // D10: using guessed type int   ServerAcceptClient(unsigned int, unsigned int);
   1221: // D40: using guessed type int close(void);
   1222: // D70: using guessed type int   SSL_free(unsigned int);
   1223: // D7C: using guessed type int   memset(unsigned int, unsigned int, unsigned int);
   1224: // E0C: using guessed type int   ntohl(unsigned int);
   1225: // E24: using guessed type int   SSL_accept(unsigned int);
   1226: // 14FD0: using guessed type int *off_14FD0;
   1227: // 14FD8: using guessed type int off_14FD8;

    910: //----- (00001DBC) --------------------------------------------------------
    911: int   sub_1DBC(int a1, int a2, const char *a3, int a4, int a5)
    912: {
    913:   int v7; // r5
    914:   int v9; // r7
    915:   const char *v10; // r9
    916:   const char *v11; // r7
    917:   int v12; // r0
    918:   const char *v13; // [sp+10h] [bp-2054h]
    919:   const char *v14; // [sp+14h] [bp-2050h]
    920:   char v17[32]; // [sp+20h] [bp-2044h] BYREF
    921:   unsigned char v18[32]; // [sp+40h] [bp-2024h] BYREF
    922:   unsigned char v19[4096]; // [sp+60h] [bp-2004h] BYREF
    923:   char _1060[4128]; // [sp+1060h] [bp-1004h] BYREF
    924: 
    925:   memset(v17, 0, sizeof(v17));
    926:   memset(v18, 0, sizeof(v18));
    927:   memset(v19, 0, sizeof(v19));
    928:   memset(_1060, 0, 4096);
    929:   v7 = a4 <= 0;
    930:   if ( !a3 )
    931:     v7 = 1;
    932:   if ( v7 )
    933:   {
    934:     debug("web-api.c", 157, 1, "data_buf or len check fail");
    935:     return -1;
    936:   }
    937:   snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.method'", a3);
    938:   get_cmd_value(v19, v18, 32);
    939:   snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.seq'", a3);
    940:   get_cmd_value(v19, v17, 32);
    941:   if ( !v18[0] )
    942:   {
    943:     debug("web-api.c", 174, 1, "get json method fail");
    944:     return -1;
    945:   }
    946:   while ( 1 )
    947:   {
    948:     v9 = 144 * v7;
    949:     if ( !safe_strcmp(&aAuth[144 * v7], v18) )
    950:       break;
    951:     if ( ++v7 == 30 )
    952:     {
    953:       snprintf(_1060, 4096, "{\"errCode\":\"1\",\"result\":\"can not find %s\",\"seq\":\"\"}", v18);
    954:       goto LABEL_23;
    955:     }
    956:   }
    957:   if ( safe_strcmp(v18, "getDevInfo") || !*off_14FE8 )
    958:   {
    959:     v13 = &aAuth[v9 + 80];
    960:     v14 = &aAuth[v9 + 112];
    961:     v10 = &aAuth[v9 + 72];
    962:     if ( *(unsigned int *)&aAuth[144 * v7 + 68] == 1 && (v11 = &aAuth[v9 + 32], safe_strlen(v11) > 0) )
    963:     {
    964:       snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.%s'", a3, v11);
    965:       get_cmd_value(v19, _1060, 4096);
    966:       snprintf(v19, 4096, "ubus -S %s %s %s '%s'", v10, v13, v14, _1060);
    967:     }
    968:     else

    910: //----- (00001DBC) --------------------------------------------------------
    911: int   sub_1DBC(int a1, int a2, const char *a3, int a4, int a5)
    912: {
    913:   int v7; // r5
    914:   int v9; // r7
    915:   const char *v10; // r9
    916:   const char *v11; // r7
    917:   int v12; // r0
    918:   const char *v13; // [sp+10h] [bp-2054h]
    919:   const char *v14; // [sp+14h] [bp-2050h]
    920:   char v17[32]; // [sp+20h] [bp-2044h] BYREF
    921:   unsigned char v18[32]; // [sp+40h] [bp-2024h] BYREF
    922:   unsigned char v19[4096]; // [sp+60h] [bp-2004h] BYREF
    923:   char _1060[4128]; // [sp+1060h] [bp-1004h] BYREF
    924: 
    925:   memset(v17, 0, sizeof(v17));
    926:   memset(v18, 0, sizeof(v18));
    927:   memset(v19, 0, sizeof(v19));
    928:   memset(_1060, 0, 4096);
    929:   v7 = a4 <= 0;
    930:   if ( !a3 )
    931:     v7 = 1;
    932:   if ( v7 )
    933:   {
    934:     debug("web-api.c", 157, 1, "data_buf or len check fail");
    935:     return -1;
    936:   }
    937:   snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.method'", a3);
    938:   get_cmd_value(v19, v18, 32);
    939:   snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.seq'", a3);
    940:   get_cmd_value(v19, v17, 32);
    941:   if ( !v18[0] )
    942:   {
    943:     debug("web-api.c", 174, 1, "get json method fail");
    944:     return -1;
    945:   }
    946:   while ( 1 )
    947:   {
    948:     v9 = 144 * v7;
    949:     if ( !safe_strcmp(&aAuth[144 * v7], v18) )
    950:       break;
    951:     if ( ++v7 == 30 )
    952:     {
    953:       snprintf(_1060, 4096, "{\"errCode\":\"1\",\"result\":\"can not find %s\",\"seq\":\"\"}", v18);
    954:       goto LABEL_23;
    955:     }
    956:   }
    957:   if ( safe_strcmp(v18, "getDevInfo") || !*off_14FE8 )
    958:   {
    959:     v13 = &aAuth[v9 + 80];
    960:     v14 = &aAuth[v9 + 112];
    961:     v10 = &aAuth[v9 + 72];
    962:     if ( *(unsigned int *)&aAuth[144 * v7 + 68] == 1 && (v11 = &aAuth[v9 + 32], safe_strlen(v11) > 0) )
    963:     {
    964:       snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.%s'", a3, v11);
    965:       get_cmd_value(v19, _1060, 4096);
    966:       snprintf(v19, 4096, "ubus -S %s %s %s '%s'", v10, v13, v14, _1060);
    967:     }
    968:     else
    969:     {
    970:       snprintf(v19, 4096, "ubus -S %s %s %s", v10, v13, v14);

    935:     return -1;
    936:   }
    937:   snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.method'", a3);
    938:   get_cmd_value(v19, v18, 32);
    939:   snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.seq'", a3);
    940:   get_cmd_value(v19, v17, 32);
    941:   if ( !v18[0] )
    942:   {
    943:     debug("web-api.c", 174, 1, "get json method fail");
    944:     return -1;
    945:   }
    946:   while ( 1 )
    947:   {
    948:     v9 = 144 * v7;
    949:     if ( !safe_strcmp(&aAuth[144 * v7], v18) )
    950:       break;
    951:     if ( ++v7 == 30 )
    952:     {
    953:       snprintf(_1060, 4096, "{\"errCode\":\"1\",\"result\":\"can not find %s\",\"seq\":\"\"}", v18);
    954:       goto LABEL_23;
    955:     }
    956:   }
    957:   if ( safe_strcmp(v18, "getDevInfo") || !*off_14FE8 )
    958:   {
    959:     v13 = &aAuth[v9 + 80];
    960:     v14 = &aAuth[v9 + 112];
    961:     v10 = &aAuth[v9 + 72];
    962:     if ( *(unsigned int *)&aAuth[144 * v7 + 68] == 1 && (v11 = &aAuth[v9 + 32], safe_strlen(v11) > 0) )
    963:     {
    964:       snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.%s'", a3, v11);
    965:       get_cmd_value(v19, _1060, 4096);
    966:       snprintf(v19, 4096, "ubus -S %s %s %s '%s'", v10, v13, v14, _1060);
    967:     }
    968:     else
    969:     {
    970:       snprintf(v19, 4096, "ubus -S %s %s %s", v10, v13, v14);
    971:     }
    972:     get_cmd_value(v19, _1060, 4096);
    973:     if ( _1060[0] )
    974:     {
    975:       snprintf(v19, 4096, "echo '%s'|jq '. + {\"seq\":\"%s\"}'", _1060, v17);
    976:       get_cmd_value(v19, _1060, 4096);
    977:     }
    978:     else
    979:     {
    980:       snprintf(_1060, 4096, "{\"errCode\":\"1\",\"result\":\"%s\",\"seq\":\"%s\"}", "ubus get empty", v17);
    981:     }
    982:   }
    983:   else
    984:   {
    985:     snprintf(_1060, 4096, "%s", off_14FE8);
    986:   }
    987: LABEL_23:
    988:   if ( !safe_strcmp(v18, "getDevInfo") && safe_strlen(_1060) > 100 && !*off_14FE8 )
    989:     snprintf(off_14FE8, 4096, "%s", _1060);
    990:   v12 = safe_strlen(_1060);
    991:   sub_1C58(a1, a2, _1060, v12, a5);
    992:   return 0;
    993: }
    994: // BE4: using guessed type int debug(unsigned int, unsigned int, unsigned int, const char *, ...);
    995: // C50: using guessed type int   get_cmd_value(unsigned int, unsigned int, unsigned int);

    942:   {
    943:     debug("web-api.c", 174, 1, "get json method fail");
    944:     return -1;
    945:   }
    946:   while ( 1 )
    947:   {
    948:     v9 = 144 * v7;
    949:     if ( !safe_strcmp(&aAuth[144 * v7], v18) )
    950:       break;
    951:     if ( ++v7 == 30 )
    952:     {
    953:       snprintf(_1060, 4096, "{\"errCode\":\"1\",\"result\":\"can not find %s\",\"seq\":\"\"}", v18);
    954:       goto LABEL_23;
    955:     }
    956:   }
    957:   if ( safe_strcmp(v18, "getDevInfo") || !*off_14FE8 )
    958:   {
    959:     v13 = &aAuth[v9 + 80];
    960:     v14 = &aAuth[v9 + 112];
    961:     v10 = &aAuth[v9 + 72];
    962:     if ( *(unsigned int *)&aAuth[144 * v7 + 68] == 1 && (v11 = &aAuth[v9 + 32], safe_strlen(v11) > 0) )
    963:     {
    964:       snprintf(v19, 4096, "echo '%s'|jsonfilter -e '@.%s'", a3, v11);
    965:       get_cmd_value(v19, _1060, 4096);
    966:       snprintf(v19, 4096, "ubus -S %s %s %s '%s'", v10, v13, v14, _1060);
    967:     }
    968:     else
    969:     {
    970:       snprintf(v19, 4096, "ubus -S %s %s %s", v10, v13, v14);
    971:     }
    972:     get_cmd_value(v19, _1060, 4096);
    973:     if ( _1060[0] )
    974:     {
    975:       snprintf(v19, 4096, "echo '%s'|jq '. + {\"seq\":\"%s\"}'", _1060, v17);
    976:       get_cmd_value(v19, _1060, 4096);
    977:     }
    978:     else
    979:     {
    980:       snprintf(_1060, 4096, "{\"errCode\":\"1\",\"result\":\"%s\",\"seq\":\"%s\"}", "ubus get empty", v17);
    981:     }
    982:   }
    983:   else
    984:   {
    985:     snprintf(_1060, 4096, "%s", off_14FE8);
    986:   }
    987: LABEL_23:
    988:   if ( !safe_strcmp(v18, "getDevInfo") && safe_strlen(_1060) > 100 && !*off_14FE8 )
    989:     snprintf(off_14FE8, 4096, "%s", _1060);
    990:   v12 = safe_strlen(_1060);
    991:   sub_1C58(a1, a2, _1060, v12, a5);
    992:   return 0;
    993: }
    994: // BE4: using guessed type int debug(unsigned int, unsigned int, unsigned int, const char *, ...);
    995: // C50: using guessed type int   get_cmd_value(unsigned int, unsigned int, unsigned int);
    996: // CB0: using guessed type int snprintf(unsigned int, unsigned int, const char *, ...);
    997: // D34: using guessed type int   safe_strcmp(unsigned int, unsigned int);
    998: // D58: using guessed type int   safe_strlen(unsigned int);
    999: // D7C: using guessed type int   memset(unsigned int, unsigned int, unsigned int);
   1000:
```

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

