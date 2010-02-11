/* A simple pthreads library emulation using Windows threads
   Arun Madhavan */

#ifdef _MSC_VER

#include <errno.h>
#include <stdio.h>

#include "types.h"
#include "functions.h"
#include "p_thread.h"

int pthread_mutex_init(pthread_mutex_t *mutex, 
    const pthread_mutexattr_t *attr)
{
	int ret = -1;
	if (attr == NULL)
	{
    pthread_mutex_t tMutex = CreateMutex(NULL, FALSE, NULL);
		if (tMutex != NULL)
		{
			ret = 0;
			*mutex = tMutex;
		}
	}
	else // Attributes not handled yet
	{
		ret = -EINVAL;
	}
	return ret;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	int ret = -1;
	if (CloseHandle(*mutex))
	{
		ret = 0;
	}
	return ret;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	int ret = -1;
	if (ReleaseMutex(*mutex))
	{
		ret = 0;
	}
	return ret;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	int ret = -1;
	DWORD dRet = WaitForSingleObject(*mutex, INFINITE);
	switch (dRet)
	{
	case WAIT_ABANDONED:
		ret = -1;
		break;

	case WAIT_OBJECT_0: // Object is in signalled state
		ret = 0;
		break;

	case WAIT_FAILED:
		ret = -1;
		break;

	default:
		ret = -1;
		break;
	}
	return ret;
}

#endif /* _MSC_VER */