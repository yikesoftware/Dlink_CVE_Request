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

## Root cause and attack path

The attack starts with an unauthenticated HTTPS request whose `Accept-Encoding` header contains an overlong gzip quality token. The HTTP parser scans the token into the 32-byte stack buffer represented by `v33`, appending bytes until the token terminator, and only afterwards calls `strtof` to interpret it.

The copy loop has no bound tied to the size of `v33`. A token longer than the buffer overwrites adjacent stack data; the PoC uses repeated `0x37` bytes, so the resulting crash record exposes attacker-controlled bytes in `BadVA=37373733`. The emulator helper only enables the native compression option and does not modify the vulnerable code.

The relevant pseudocode is embedded below. It shows the request value being read, transformed or copied, and reaching the vulnerable sink.

```c
/* IDA pseudocode excerpt; addresses are from the analyzed firmware. */
   7465:             v111 = *(unsigned short *)(_ctype_b + 2 * v4[11]) & 0x20;
   7466:             v150[8] = 99;
   7467:             if ( v111 )
   7468:             {
   7469:               v112 = v4 + 12;
   7470:               while ( *(unsigned short *)(_ctype_b + 2 * *v112++) & 0x20 )
   7471:                 ;
   7472:               v110 = v112 - 1;
   7473:             }
   7474:             if ( strstr(v110, "Trident/") )
   7475:             {
   7476:               v150[8] = 1;
   7477:             }
   7478:             else if ( strstr(v110, "Safari/") )
   7479:             {
   7480:               v150[8] = 6;
   7481:             }
   7482:             else if ( strstr(v110, "mydlink-agent") )
   7483:             {
   7484:               v150[8] = 8;
   7485:             }
   7486:             goto LABEL_137;
   7487:           }
   7488:           if ( !strncasecmp(v4, "Accept-Encoding:", 16) )
   7489:           {
   7490:             v114 = v4[16];
   7491:             v115 = v4 + 16;
   7492:             while ( (*(unsigned short *)(_ctype_b + 2 * v114) & 0x20) != 0 )
   7493:               v114 = *++v115;
   7494:             free(v150[7]);
   7495:             v150[7] = strdup(v115);
   7496:             goto LABEL_137;
   7497:           }
   7498:           if ( strncasecmp(v4, "Authorization:", 14) )
   7499:             break;
   7500:           v116 = v4[14];
   7501:           v117 = v4 + 14;
   7502:           while ( (*(unsigned short *)(_ctype_b + 2 * v116) & 0x20) != 0 )
   7503:             v116 = *++v117;
   7504:           v118 = strncasecmp(v117, "Basic", 5);
   7505:           v50 = v163;
   7506:           if ( !v118 )
   7507:           {
   7508:             if ( v150[10] != 7 && (unsigned int)strlen(v117) >= 0x201 )
   7509:             {
   7510:               v5 = v172;
   7511:               v120 = fileno(stdin);
   7512:               if ( isatty(v120) )
   7513:                 puts("Invalid Authorization data");
   7514:               syslog(14, "Invalid Authorization data\n");
   7515:               v13 = 0;
   7516:               goto LABEL_15;
   7517:             }
   7518:             v119 = (int)(v117 + 5);
   7519:             sub_403DA0(v119);
   7520:             *(unsigned char *)strchr(v119, 58) = 0;
   7521:             goto LABEL_137;
   7522:           }
   7523:         }
   7524:         if ( !strncasecmp(v4, "API-AUTH:", 9) )
   7525:         {

   5482:       if ( !*(unsigned char *)(v8 + 1) )
   5483:       {
   5484:         HIBYTE(v33[0]) = 0;
   5485:         v16 = 1065353216;
   5486: LABEL_10:
   5487:         if ( v10 <= 0 )
   5488:           goto LABEL_30;
   5489:         goto LABEL_11;
   5490:       }
   5491:       v12 = _ctype_b;
   5492:       v13 = 0;
   5493:       v14 = 0;
   5494:       while ( v9 != 61 || *(v11 - 1) != 113 )
   5495:       {
   5496:         v15 = v13 != 0;
   5497:         v13 = 0;
   5498:         if ( v15 )
   5499:           goto LABEL_26;
   5500: LABEL_8:
   5501:         v9 = *++v11;
   5502:         if ( !v9 )
   5503:           goto LABEL_9;
   5504:       }
   5505:       ++v11;
   5506: LABEL_26:
   5507:       v30 = *v11;
   5508:       v13 = 1;
   5509:       if ( v30 != 59 )
   5510:       {
   5511:         if ( (*(unsigned short *)(v12 + 2 * v30) & 0x20) == 0 )
   5512:           *((unsigned char *)v33 + v14++) = v30;
   5513:         goto LABEL_8;
   5514:       }
   5515: LABEL_9:
   5516:       *((unsigned char *)v33 + v14) = 0;
   5517:       v16 = 1065353216;
   5518:       if ( !HIBYTE(v33[0]) )
   5519:         goto LABEL_10;
   5520:       v38 = v8 - v5;
   5521:       v31 = strtof(v33, 0, 61);
   5522:       v10 = v38;
   5523:       v16 = v31;
   5524:       if ( v38 <= 0 )
   5525:       {
   5526: LABEL_30:
   5527:         HIBYTE(v35[0]) = 0;
   5528:         v32 = sub_4BC118(v16, v6);
   5529:         v25 = a3;
   5530:         if ( v32 <= 0 )
   5531:         {
   5532:           v24 = a4;
   5533:           goto LABEL_32;
   5534:         }
   5535: LABEL_17:
   5536:         if ( v25 > 0 )
   5537:         {
   5538:           v26 = 0;
   5539:           v27 = a2;
   5540:           do
   5541:           {
   5542:             v28 = *v27;
```

## Suggested remediation

Validate and constrain the affected input before invoking the privileged operation.

