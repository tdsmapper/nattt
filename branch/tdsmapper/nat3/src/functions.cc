#include "functions.h"
#include <errno.h>

#ifndef _MSC_VER

int GetLastError()
{
  return errno;
}


#endif /* _MSC_VER */
