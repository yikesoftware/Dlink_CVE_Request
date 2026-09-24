/* Pseudocode relocated in DIR-825M firmware 1.1.8.6. */
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
