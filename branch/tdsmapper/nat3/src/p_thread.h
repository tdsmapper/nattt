#ifndef __P_THREAD_H__
#define __P_THREAD_H__
/* A "Windows implementation" of pthreads */
#include "types.h"

#ifdef _MSC_VER

/* The type that is to be returned when SpawnResolver exits */
typedef HANDLE pthread_t;
typedef HANDLE pthread_mutex_t;
typedef DWORD  pthread_attr_t;
typedef int    pthread_mutexattr_t;

int pthread_mutex_init(pthread_mutex_t *mutex, 
    const pthread_mutexattr_t *attr);

int pthread_mutex_destroy(pthread_mutex_t *mutex);

int pthread_mutex_unlock(pthread_mutex_t *mutex); 

int pthread_mutex_lock(pthread_mutex_t *mutex); 

#endif /* _MSC_VER */
#endif /* __P_THREAD_H__ */