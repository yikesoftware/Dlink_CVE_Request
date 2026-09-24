/* IDA pseudocode; addresses and line numbers are documented in case.json. */
  18250: //----- (00419E00) --------------------------------------------------------
  18251: int   sub_419E00(unsigned int *a1, int a2)
  18252: {
  18253:   const char *v4; // $s0
  18254:   const char *v5; // $s1
  18255:   char v7[260]; // [sp+18h] [-104h] BYREF
  18256: 
  18257:   memset(v7, 0, 256);
  18258:   v4 = (const char *)sub_40F4CC(a1, (int)"host", (int)"");
  18259:   v5 = (const char *)sub_40F4CC(a1, (int)"ipVer", (int)"");
  18260:   if ( !v4 || *v4 )
  18261:   {
  18262:     unlink("/var/tmp/tracerouteDiagnosticResult");
  18263:     sprintf(v7, "traceroute -%s %s -w 2 -m 20 &> /var/tmp/tracerouteDiagnosticResult", v5, v4);
  18264:     fprintf(stderr, "%s\n", v7);
  18265:     system(v7);
  18266:     return 0;
  18267:   }
  18268:   else
  18269:   {
  18270:     strcpy(a2, "Host is Error!");
  18271:     return -1;
  18272:   }
  18273: }
  18274: // 480050: using guessed type int   unlink(unsigned int);
  18275: // 4800E0: using guessed type int fprintf(unsigned int, const char *, ...);
  18276: // 480290: using guessed type int   memset(unsigned int, unsigned int, unsigned int);
  18277: // 4803D0: using guessed type int   strcpy(unsigned int, unsigned int);
  18278: // 480420: using guessed type int   system(unsigned int);
  18279: // 4807A0: using guessed type int sprintf(unsigned int, const char *, ...);
  18280: // 493CFC: using guessed type int stderr;
  18281:
