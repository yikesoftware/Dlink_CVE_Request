/* IDA pseudocode; addresses and line numbers are documented in case.json. */
  49521:   int v56; // [sp+1F4h] [-24h] BYREF
  49522:   int v57[2]; // [sp+1F8h] [-20h] BYREF
  49523:   int v58; // [sp+200h] [-18h]
  49524:   int v59; // [sp+204h] [-14h]
  49525:   int v60; // [sp+208h] [-10h]
  49526:   int v61; // [sp+20Ch] [-Ch]
  49527:   int v62; // [sp+210h] [-8h]
  49528: 
  49529:   v55 = 1;
  49530:   v54 = 1;
  49531:   v2 = wlan_idx;
  49532:   v47 = 0;
  49533:   v48 = 0;
  49534:   v49 = 0;
  49535:   v50 = 0;
  49536:   v51 = 0;
  49537:   v53 = 0;
  49538:   v52 = 0;
  49539:   sub_428EF8("wlan0");
  49540:   apmib_get(59, &v55);
  49541:   apmib_get(22, &v53);
  49542:   v62 = 4653056;
  49543:   sub_428EF8("wlan1");
  49544:   apmib_get(59, &v54);
  49545:   apmib_get(22, &v52);
  49546:   sprintf(v45, "wlan%d", wlan_idx);
  49547:   sub_428EF8(v45);
  49548:   wlan_idx = v2;
  49549:   memset(v46, 0, 30);
  49550:   v3 = (unsigned char *)sub_40F4CC(a1, (int)"targetAPMac", (int)"");
  49551:   v4 = (char *)sub_40F4CC(a1, (int)"targetAPSsid", (int)"");
  49552:   v5 = (char *)sub_40F4CC(a1, (int)"submit-url", (int)"");
  49553:   if ( *(unsigned char *)sub_40F4CC(a1, (int)"resetUnCfg", (int)"") == 49 )
  49554:   {
  49555:     v6 = 0;
  49556:     if ( sub_429810(2) )
  49557:     {
  49558:       v6 = 1;
  49559:       swapWlanMibSetting(0, 1u);
  49560:     }
  49561:     v7 = *(unsigned char *)(pMib + 91461);
  49562:     v58 = *(unsigned char *)(pMib + 91454);
  49563:     v59 = *(unsigned char *)(pMib + 111788);
  49564:     v8 = *(unsigned char *)(pMib + 111795);
  49565:     v9 = *(unsigned char *)(pMib + 93542);
  49566:     v61 = *(unsigned char *)(pMib + 113876);
  49567:     v62 = v7;
  49568:     v60 = v8;
  49569:     printf("(%s,%d)Reset to OOB ...\n", "formWsc", 10626);
  49570:     v10 = v60;
  49571:     if ( v62 != 1 )
  49572:     {
  49573:       sub_44CA90("wlan0");
  49574:       v11 = pMib + 0x10000;
  49575:       v12 = v58;
  49576:       *(unsigned char *)(pMib + 93542) = v9;
  49577:       *(unsigned char *)(v11 + 25918) = v12;
  49578:       v10 = v60;
  49579:     }
  49580:     if ( v10 != 1 )
  49581:     {

  49718:           v29 = *v28;
  49719:           if ( sub_441000(*v28) )
  49720:             *((unsigned char *)v44 + v25++) = v29;
  49721:         }
  49722:         *((unsigned char *)v44 + v25) = 0;
  49723:         if ( strlen(v44) == 12 )
  49724:         {
  49725:           sprintf(v45, "iwpriv wlan%d set_mib wsc_specmac=%s ", wlan_idx, (const char *)v44);
  49726:           system(v45);
  49727:         }
  49728:         else
  49729:         {
  49730:           puts("invaild MAC Addr Len\n");
  49731:         }
  49732:         v24 = *v4;
  49733:       }
  49734:       else
  49735:       {
  49736:         v24 = *v4;
  49737:       }
  49738:       v30 = v24 == 0;
  49739:       v31 = v55;
  49740:       if ( !v30 )
  49741:       {
  49742:         if ( (unsigned int)strlen(v4) < 0x21 )
  49743:         {
  49744:           memset(v44, 0, 128);
  49745:           strcpy(v44, v4);
  49746:           sub_42AE10(v44);
  49747:           snprintf(v45, 200, "iwpriv wlan%d set_mib wsc_specssid=\"%s\" ", wlan_idx, (const char *)v44);
  49748:           system(v45);
  49749:         }
  49750:         else
  49751:         {
  49752:           puts("invaild SSID Len");
  49753:         }
  49754:         v31 = v55;
  49755:       }
  49756:       if ( v31 )
  49757:       {
  49758:         v32 = wlan_idx;
  49759:       }
  49760:       else
  49761:       {
  49762:         v32 = wlan_idx;
  49763:         if ( !v54 )
  49764:         {
  49765:           v32 = wlan_idx;
  49766:           if ( !v53 )
  49767:           {
  49768:             if ( !v52 )
  49769:             {
  49770:               snprintf(v45, 200, "%s -sig_start %s", "wscd", "wlan0-wlan1");
  49771: LABEL_84:
  49772:               system(v45);
  49773:               v34 = v56;
  49774:               goto LABEL_74;
  49775:             }
  49776:             v32 = wlan_idx;
  49777:           }
  49778:         }
