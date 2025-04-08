#include "tsk_thread.h"

// mingw's pthread.h will try to read a config.h if HAVE_CONFIG_H
#undef HAVE_CONFIG_H

#include <pthread.h>
#include <assert.h>

TskThread::~TskThread()
{
    // empty
}

static void *x_thread_top(void *ta)
{
    TskThread *thread = (TskThread *)ta;
    (*thread)();
    return 0;
}

void TskThread::run(TskThread** threads, size_t nthreads)
{
    pthread_t* the_threads = new pthread_t[nthreads];
    pthread_attr_t pat;
    pthread_attr_init(&pat);
    for(size_t p = 0; p < nthreads; p++) {
        pthread_t tid;
        int pt = pthread_create(&tid, 0, x_thread_top, threads[p]);
        assert(0 == pt);
        the_threads[p] = tid;
    }
    /* It's quite annoying, you can't wait for more than one in pthreads. */
    for(size_t p = 0; p < nthreads; p++) {
        void *thread_return;
        int pt;
        pt = pthread_join(the_threads[p], &thread_return);
        assert(0 == pt);
        assert(0 == thread_return);
    }
    pthread_attr_destroy(&pat);
    delete[] the_threads;
}
