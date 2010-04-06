/* Just a simple log file utility */
#include <stdio.h>
#include <string.h>
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
      printf("The log file is: %s\n", szLogFile);
      fLog = fopen(szLogFile, "a");
      if (!fLog)
      {
         fprintf(stderr, "There was a problem opening the log file %s. Do you have permissions?\n", szLogFile);
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
