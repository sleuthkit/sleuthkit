#ifndef _TSK_THREAD_H
#define _TSK_THREAD_H

#include <stddef.h>

// If we ever want to run on Windows too, this interface will do.
// Just fill out a win32 version.
class TskThread {
public:
    virtual ~TskThread();
    virtual void operator()() = 0;
    static void run(TskThread** threads, size_t nthreads);
};

#endif
