/* Function rewriting between Windows and Linux/BSD */

#ifndef __FUNCTIONS_H__
#define __FUNCTIONS_H__


/* Networking/file operations */
#ifdef _MSC_VER
#define CLOSESOCKET(x) closesocket(x)
#define CLOSEDEVICE(x)   CloseHandle(x)
#else
#define CLOSESOCKET(x) close(x)
#define CLOSEDEVICE(x)   close(x) 
#endif

#ifdef _MSC_VER
#define snprintf(A,...) _snprintf(A, __VA_ARGS__)
#else
#define snprintf(A,...) snprintf(A, __VA_ARGS__)

int GetLastError()
{
  return errno;
}
#endif /* _MSC_VER */

#define err(value,cmdname) eprintf(cmdname " - err value is %d\n", value)

#endif /* __FUNCTIONS_H__ */