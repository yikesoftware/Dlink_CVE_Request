/* IDA pseudocode; addresses and line numbers are documented in case.json. */
   7090:       ++v46;
   7091:       v45 += 60;
   7092:     }
   7093:     while ( v46 < dword_4ED468 );
   7094:     v43 = v162;
   7095:   }
   7096:   v44 = v43;
   7097: LABEL_131:
   7098:   if ( !strcmp(v44, "uir") )
   7099:     v3[1] = dword_4ED464;
   7100:   v49 = *(unsigned int *)(dword_4F21EC + 140);
   7101:   v150[12] = v3[2];
   7102:   v150[9] = v49;
   7103:   if ( !strcmp(v43, "DHMAPI") && v150[3] == 1 )
   7104:     v150[3] = 9;
   7105:   v150[8] = 1;
   7106:   v11 = v153;
   7107:   v172 = v5;
   7108: LABEL_137:
   7109:   while ( 2 )
   7110:   {
   7111:     v50 = v163;
   7112:     while ( 1 )
   7113:     {
   7114:       while ( 1 )
   7115:       {
   7116:         while ( 1 )
   7117:         {
   7118:           while ( 1 )
   7119:           {
   7120:             if ( v50 < 0 || sub_406074(v4, v164) <= 0 )
   7121:             {
   7122:               v5 = v172;
   7123:               if ( !strcasecmp(&v156, "POST") )
   7124:               {
   7125:                 v66 = v157;
   7126:                 if ( v157 )
   7127:                 {
   7128:                   v67 = v158;
   7129:                   v68 = v162;
   7130:                   if ( v158 )
   7131:                   {
   7132:                     if ( strcmp(v162, "syslog") && strcmp(v68, "quickvpn") )
   7133:                     {
   7134:                       if ( strncasecmp(v67, "application/x-www-form-urlencoded", 33) )
   7135:                       {
   7136:                         if ( strncasecmp(v67, "multipart/form-data", 19) )
   7137:                         {
   7138:                           if ( !strncasecmp(v67, "text/xml", 8) )
   7139:                             v150[3] = 10;
   7140:                         }
   7141:                         else
   7142:                         {
   7143:                           v150[3] = 3;
   7144:                         }
   7145:                       }
   7146:                       else
   7147:                       {
   7148:                         v150[3] = 2;
   7149:                         v82 = malloc(v66 + 1);
   7150:                         v83 = v82;

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
   7526:           v121 = v4[9];
   7527:           v122 = v4 + 9;
   7528:           while ( (*(unsigned short *)(_ctype_b + 2 * v121) & 0x20) != 0 )
   7529:             v121 = *++v122;
   7530:           free(v150[53]);
   7531:           v150[53] = strdup(v122);
   7532:           goto LABEL_137;
   7533:         }
   7534:         if ( !strncasecmp(v4, "API-Content:", 12) )
   7535:         {
   7536:           v123 = v4[12];
   7537:           v124 = v4 + 12;
   7538:           while ( (*(unsigned short *)(_ctype_b + 2 * v123) & 0x20) != 0 )
   7539:             v123 = *++v124;
   7540:           free(v150[55]);
   7541:           v150[55] = strdup(v124);
   7542:           goto LABEL_137;
   7543:         }
   7544:         if ( !strncasecmp(v4, "API-Action:", 11) )
   7545:         {
   7546:           v125 = v4 + 11;
   7547:           v126 = strchr(v4 + 11, 34);
   7548:           if ( !v126 )
   7549:           {
   7550:             for ( i = v4[11]; (*(unsigned short *)(_ctype_b + 2 * i) & 0x20) != 0; i = *v125 )
