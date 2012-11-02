/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk_base_i.h"

#ifdef TSK_MULTITHREAD_LIB

#ifdef TSK_WIN32

void
tsk_init_lock(tsk_lock_t * lock)
{
    InitializeCriticalSection(&lock->critical_section);
}

void
tsk_deinit_lock(tsk_lock_t * lock)
{
    DeleteCriticalSection(&lock->critical_section);
}

void
tsk_take_lock(tsk_lock_t * lock)
{
    EnterCriticalSection(&lock->critical_section);
}

void
tsk_release_lock(tsk_lock_t * lock)
{
    LeaveCriticalSection(&lock->critical_section);
}

#else

#include <assert.h>

void
tsk_init_lock(tsk_lock_t * lock)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);

    // Locks on Linux are not recursive (unlike on Windows), so things
    // will hang if the current thread tries to take the lock again.
    // While debugging, it's sometimes useful to call
    //
    //  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK_NP);
    //
    // which will provoke an immediate error rather than a hang.
    //
    // PTHREAD_MUTEX_ERRORCHECK is not defined by default on Linux,
    // but it is portable if you have the right_XOPEN_SOURCE settings.
    // However, that macro affects the availability of other features
    // like BSD-style u_int types used in afflib.
    // PTHREAD_MUTEX_ERRORCHECK -is- available by default on Mac.
    //
    // PTHREAD_MUTEX_ERRORCHECK_NP is the Linux/gcc non-portable
    // equivalent which does not require _XOPEN_SOURCE.
    //
    // Other interesting attributes are PTHREAD_MUTEX_RECURSIVE (and
    // PTHREAD_MUTEX_RECURSIVE_NP).  We avoided those out of portability
    // concerns with the _XOPEN_SOURCE settings.

    int e = pthread_mutex_init(&lock->mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    if (e != 0) {
        fprintf(stderr, "tsk_init_lock: thread_mutex_init failed %d\n", e);
        assert(0);
    }
}

void
tsk_deinit_lock(tsk_lock_t * lock)
{
    pthread_mutex_destroy(&lock->mutex);
}

void
tsk_take_lock(tsk_lock_t * lock)
{
    int e = pthread_mutex_lock(&lock->mutex);
    if (e != 0) {
        fprintf(stderr, "tsk_take_lock: thread_mutex_lock failed %d\n", e);
        assert(0);
    }
}

void
tsk_release_lock(tsk_lock_t * lock)
{
    int e = pthread_mutex_unlock(&lock->mutex);
    if (e != 0) {
        fprintf(stderr,
            "tsk_release_lock: thread_mutex_unlock failed %d\n", e);
        assert(0);
    }
}

#endif

    // single-threaded
#else

void
tsk_init_lock(tsk_lock_t * lock)
{
}

void
tsk_deinit_lock(tsk_lock_t * lock)
{
}

void
tsk_take_lock(tsk_lock_t * lock)
{
}

void
tsk_release_lock(tsk_lock_t * lock)
{
}

#endif
