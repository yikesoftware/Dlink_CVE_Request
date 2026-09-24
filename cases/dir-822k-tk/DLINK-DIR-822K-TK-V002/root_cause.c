/* IDA pseudocode; addresses and line numbers are documented in case.json. */
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
