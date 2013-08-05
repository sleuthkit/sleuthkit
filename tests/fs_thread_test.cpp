// This file implements a thread test for the fs layer.  The program
// opens a file system and then launches N threads.  Each thread walks
// through the same shared file system (TSK_FS_INFO) and produces an
// output file named "thread-N.log".  The actual format of the output
// doesn't really matter.  All we need is for the output to be
// different if we hit race conditions.
//
// To turn this into a thread test, the caller (e.g. Makefile or
// script) should arrange to run the program as follows:
// 
//   run with one thread; produce thread-0.log; rename to base.log
//   run with N threads; produce thread-0.log, thread-1.log, etc.
//   diff base.log thread-0.log
//   diff base.log thread-1.log
//   ...
//
// The test passes if all of the thread-N.log files are identical to
// the base.log file.  Of course, this does not guarantee thread
// safety, but by running enough threads and enough repetitions of
// the test without error, you can be more confident.

#include <tsk/libtsk.h>

#include "tsk_thread.h"

// for tsk_getopt() and friends
#include "tsk/base/tsk_base_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static TSK_WALK_RET_ENUM
proc_dir(TSK_FS_FILE* fs_file, const char* path, void* stuff)
{
    FILE* log = (FILE*)stuff;
    
    fprintf(log, "%s%s: flags: %d, addr: %d", path, fs_file->name->name,
            fs_file->meta->flags, (int)fs_file->meta->addr);
    
    // hmm, not sure if the ntfs sid stuff is working at all, but at
    // least call it to detect possible hangs
    if (fs_file->fs_info->fread_owner_sid) {
        char* sid_str = 0;
        if (tsk_fs_file_get_owner_sid(fs_file, &sid_str)) {
            if (tsk_verbose) {
                tsk_error_print(stderr);
            }
        } else {
            fprintf(log, ", sid_str: %s\n", sid_str);
            free(sid_str);
        }
    }
    fputc('\n', log);

    if (fs_file->meta->type == TSK_FS_META_TYPE_REG) {
        char buf[2048];
        size_t len = 0;
        for (TSK_OFF_T off = 0; off < fs_file->meta->size; off += len) {
            if (fs_file->meta->size - off < (TSK_OFF_T)sizeof(buf)) {
                len = (size_t) (fs_file->meta->size - off);
            } else {
                len = sizeof(buf);
            }

            int myflags = 0;    
            ssize_t cnt = tsk_fs_file_read(fs_file, off, buf, len, (TSK_FS_FILE_READ_FLAG_ENUM)myflags);
            if (cnt == -1) {
                if (tsk_verbose) {
                    fprintf(stderr, "Error reading %s file: %s\n",
                            ((fs_file->name->
                              flags & TSK_FS_NAME_FLAG_UNALLOC)
                             || (fs_file->meta->
                                 flags & TSK_FS_META_FLAG_UNALLOC)) ?
                            "unallocated" : "allocated",
                            fs_file->name->name);
                    tsk_error_print(stderr);
                }
                break;
            } else if (cnt != (ssize_t) len) {
                if (tsk_verbose) {
                    fprintf(stderr,
                            "Warning: %" PRIuSIZE " of %" PRIuSIZE
                            " bytes read from %s file %s\n", cnt, len,
                            ((fs_file->name->
                              flags & TSK_FS_NAME_FLAG_UNALLOC)
                             || (fs_file->meta->
                                 flags & TSK_FS_META_FLAG_UNALLOC)) ?
                            "unallocated" : "allocated",
                            fs_file->name->name);
                }
            }

            // data is in buf[0..len); could be binary, not null terminated
            // might consider printing it out if all ascii or looks like text
            // or print hexdump, just for thread comparison
        }
    }

    return TSK_WALK_CONT;
}

static void
proc_fs(TSK_FS_INFO* fs, FILE* log)
{
    // Walk starting at $OrphanFiles to provoke recursive call to tsk_fs_dir_load_inum_named.
    if (tsk_fs_dir_walk(fs, TSK_FS_ORPHANDIR_INUM(fs), TSK_FS_DIR_WALK_FLAG_RECURSE, proc_dir, log)) {
        fprintf(stderr, "dir walk from $OrphanFiles failed\n");
        tsk_error_print(stderr);
    }

    // Walk starting at the root.  Note that we walk the root tree
    // -after- the $OrphanFile because if we use the other order,
    // things are already cached.
    if (tsk_fs_dir_walk(fs, fs->root_inum, TSK_FS_DIR_WALK_FLAG_RECURSE, proc_dir, log)) {
        fprintf(stderr, "dir walk from root failed\n");
        tsk_error_print(stderr);
    }
}

class MyThread : public TskThread {
public:
    // The threads share the same TSK_FS_INFO
    MyThread(int id, TSK_FS_INFO* fs, size_t niters) :
        m_id(id), m_fs(fs), m_niters(niters) {}

    void operator()() {
        // We rewrite the log on every iteration to prevent truly huge
        // logs files.
        char logname[256];
        sprintf(logname, "thread-%d.log", m_id);
        for (size_t i = 0; i < m_niters; ++i) {
            FILE* log = fopen(logname, "w");
            if (log == 0) {
                perror(logname);
                exit(1);
            }
            proc_fs(m_fs, log);
            fclose(log);
        }
    }
private:
    int m_id;
    TSK_FS_INFO* m_fs;
    size_t m_niters;

    // disable copy and assignment
    MyThread(const MyThread&);
    MyThread& operator=(const MyThread&);
};

static const TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr, _TSK_T("Usage: %s [-f fstype ] [-o imgoffset ] [-v] image nthreads niters\n"), progname);

    exit(1);
}

int
main(int argc, char** argv1)
{
    
    TSK_TCHAR **argv;
    TSK_TCHAR *cp;

#ifdef TSK_WIN32
    // On Windows, get the wide arguments (mingw doesn't support wmain)
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        fprintf(stderr, "Error getting wide arguments\n");
        exit(1);
    }
#else
    argv = (TSK_TCHAR **) argv1;
#endif

    progname = argv[0];

    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;
    TSK_OFF_T imgaddr = 0;
    int ch;
    while ((ch = GETOPT(argc, argv, _TSK_T("f:o:v"))) != -1) {
        switch (ch) {
        case _TSK_T('f'):
            fstype = tsk_fs_type_toid(OPTARG);
            if (fstype == TSK_FS_TYPE_UNSUPP) {
                TFPRINTF(stderr,
                         _TSK_T("Unsupported file system type: %s\n"), OPTARG);
                usage();
            }
            break;
        case _TSK_T('o'):
            if ((imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;
        case _TSK_T('v'):
            tsk_verbose = 1;
            break;
        default:
            usage();
            break;
        }
    }
    if (argc - OPTIND != 3) {
        usage();
    }

    const TSK_TCHAR* image = argv[OPTIND];
    size_t nthreads = (size_t) TSTRTOUL(argv[OPTIND + 1], &cp, 0);
    if (nthreads == 0) {
        fprintf(stderr, "invalid nthreads\n");
        exit(1);
    }
    size_t niters = (size_t) TSTRTOUL(argv[OPTIND + 2], &cp, 0);
    if (niters == 0) {
        fprintf(stderr, "invalid nthreads\n");
        exit(1);
    }
    
    TSK_IMG_INFO* img = tsk_img_open_sing(image, TSK_IMG_TYPE_DETECT, 0);
    if (img == 0) {
        tsk_error_print(stderr);
        exit(1);
    }

    if ((imgaddr * img->sector_size) >= img->size) {
        tsk_fprintf(stderr, "Sector offset supplied is larger than disk image (maximum: %"
                PRIu64 ")\n", img->size / img->sector_size);
        exit(1);
    }

    TSK_FS_INFO* fs = tsk_fs_open_img(img, imgaddr * img->sector_size, fstype);
    if (fs == 0) {
        tsk_img_close(img);
        tsk_error_print(stderr);
        exit(1);
    }

    TskThread** threads = new TskThread*[nthreads];
    for (size_t i = 0; i < nthreads; ++i) {
        threads[i] = new MyThread(i, fs, niters);
    }
    TskThread::run(threads, nthreads);
    for (size_t i = 0; i < nthreads; ++i) {
        delete threads[i];
    }
    delete[] threads;
    
    tsk_fs_close(fs);
    tsk_img_close(img);
    exit(0);
}
