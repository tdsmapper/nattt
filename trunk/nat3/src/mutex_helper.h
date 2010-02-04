#ifndef _MUTEX_HELPER_H
#define _MUTEX_HELPER_H

#ifndef _MSC_VER
#include <pthread.h>
#else
#include "p_thread.h" // A "Windows implementation" of pthreads
#endif

class MutexHelper
{
  // Member Variables
  private:
    pthread_mutex_t &m_tMutex;

  // Methods
  public:
    MutexHelper(pthread_mutex_t &p_tMutex);
    virtual ~MutexHelper();

};

#endif

