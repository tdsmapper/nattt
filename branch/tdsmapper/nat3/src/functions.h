/* Function rewriting between Windows and Linux/BSD */

#ifndef __FUNCTIONS_H__
#define __FUNCTIONS_H__
#include "types.h"
#include <stdio.h>


/* Windows only functions */
#ifdef _MSC_VER
  #define CLOSESOCKET(x) closesocket(x)
  #define CLOSEDEVICE(x) CloseHandle(x)
  #define snprintf(A,...) _snprintf(A, __VA_ARGS__)
/* *NIX only functions */
#else
  #define CLOSESOCKET(x) close(x)
  #define CLOSEDEVICE(x) close(x) 
  #define snprintf(A,...) snprintf(A, __VA_ARGS__)
  int GetLastError();
  #define stricmp strcasecmp
#endif

/* Common functions */
#define err(value,cmdname) eprintf(cmdname " - err value is %d\n", value)
bool net_itoa(uint32_t p_uIP, char *p_szOutput);
bool GetInterfaceMacAddress(char *pIface, unsigned char cMacAddr[]);

#endif /* __FUNCTIONS_H__ */
