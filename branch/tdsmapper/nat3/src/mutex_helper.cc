#include <stdio.h>
#include <string.h>

#include "types.h"
#include "mutex_helper.h"
#include "functions.h"
#include "log.h"

MutexHelper::MutexHelper(pthread_mutex_t &p_tMutex)
  : m_tMutex(p_tMutex)
{
  int iErr = pthread_mutex_lock(&m_tMutex);
  if (0 != iErr)
  {
    eprintf( "%s [%d] - Unable to LOCK mutex: [%d] %s\n",
            __FILE__,
            __LINE__,
            iErr,
            strerror(iErr));
  }
}

MutexHelper::~MutexHelper()
{
  int iErr = pthread_mutex_unlock(&m_tMutex);
  if (0 != iErr)
  {
    eprintf( "%s [%d] - Unable to UNLOCK mutex: [%d] %s\n",
            __FILE__,
            __LINE__,
            iErr,
            strerror(iErr));
  }
}

