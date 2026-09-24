/* Pseudocode relocated in DIR-825M firmware 1.1.8.6. */
 20361: //----- (0041CE08) --------------------------------------------------------
 20362: int   sub_41CE08(unsigned int *a1, int a2)
 20363: {
 20364:   const char *v4; // $v0
 20365:   const char *v5; // $s0
 20366:   int result; // $v0
 20367:   unsigned char v7[260]; // [sp+18h] [-104h] BYREF
 20368: 
 20369:   memset(v7, 0, 256);
 20370:   v4 = (const char *)sub_41351C(a1, (int)"host", (int)"");
 20371:   v5 = v4;
 20372:   if ( !v4 || *v4 )
 20373:   {
 20374:     result = strncmp(v4, "top", 3);
 20375:     if ( result )
 20376:     {
 20377:       result = strncmp(v5, "ping", 4);
 20378:       if ( result )
 20379:       {
 20380:         result = strcmp(v5, "flash all");
 20381:         if ( result )
 20382:         {
 20383:           unlink("/var/tmp/debugDiagnosticResult");
 20384:           sprintf(v7, "%s &> /var/tmp/debugDiagnosticResult", v5);
 20385:           system(v7);
 20386:           return 0;
