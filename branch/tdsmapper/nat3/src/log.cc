/* Just a simple log file utility */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "log.h"

FILE *fLog;

void open_log_file(char szLogFile[])
{
   /* Allow for stderr logging */
   if (!strcmp(szLogFile, "stderr"))
   {
	   fLog = stderr;
	   return;
   }
   else
   {
      char logFile[256];
      if (!strcmp(szLogFile, "none"))
      {
         /* NULL devices for Windows and *NIX */
#ifdef _MSC_VER
         strcpy(logFile, "nul");
#else
         strcpy(logFile, "/dev/null");
#endif
      }
      else
      {
         strncpy(logFile, szLogFile, sizeof(logFile));
      }

      fLog = fopen(logFile, "a");
      if (!fLog)
      {
         fprintf(stderr, "There was a problem opening the log file %s. Do you have permissions?\n", szLogFile);
         abort();
      }
      else
      {
         fprintf(fLog, "----------------------------------------------\n");
         time_t currentTime = time((time_t*)NULL);
         char* pszTime = ctime(&currentTime);
         eprintf("NAT3D run on day %s\n", pszTime);
      }
   }
}
