/* Pseudocode relocated in DIR-825M firmware 1.1.8.6. */
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
