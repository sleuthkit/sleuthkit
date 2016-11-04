/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2013 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file hfind.c
 * Command line tool to index and lookup values in a hash database
 */
#include "tsk/tsk_tools_i.h"
#include <locale.h>

static TSK_TCHAR *progname;

/**
 * Print usage instructions.
 */
static void
usage()
{
    TFPRINTF(stderr,
             _TSK_T
             ("usage: %s [-eqVa] [-c] [-f lookup_file] [-i db_type] db_file [hashes]\n"),
             progname);
    tsk_fprintf(stderr,
                "\t-e: Extended mode - where values other than just the name are printed\n");
    tsk_fprintf(stderr,
                "\t-q: Quick mode - where a 1 is printed if it is found, else 0\n");
    tsk_fprintf(stderr, "\t-V: Print version to STDOUT\n");
    tsk_fprintf(stderr, "\t-c db_name: Create new database with the given name.\n");
    tsk_fprintf(stderr, "\t-a: Add given hashes to the database.\n");
    tsk_fprintf(stderr,
                "\t-f lookup_file: File with one hash per line to lookup\n");
    tsk_fprintf(stderr,
                "\t-i db_type: Create index file for a given hash database type\n");
    tsk_fprintf(stderr,
                "\tdb_file: The path of the hash database, must have .kdb extension for -c option\n");
    tsk_fprintf(stderr,
                "\t[hashes]: hashes to lookup (STDIN is used otherwise)\n");
    tsk_fprintf(stderr, "\n\tSupported index types: %s\n",
                TSK_HDB_DBTYPE_SUPPORT_STR);
    exit(1);
}

/**
 * Lookup callback to print the names of the files for each hash that is found.
 */
static TSK_WALK_RET_ENUM
lookup_act(TSK_HDB_INFO * hdb_info, const char *hash, const char *name, void *ptr)
{
    tsk_fprintf(stdout, "%s\t%s\n", hash, (NULL != name) ? name : "File name not available");
    return TSK_WALK_CONT;
}

/**
 * Print a message if a hash is not found.  Placed here so that it is easier to change
 * output format for hits and misses.
 */
static void
print_notfound(char *hash)
{
    tsk_fprintf(stdout, "%s\tHash Not Found\n", hash);
}

int
main(int argc, char ** argv1)
{
    int ch;
    TSK_TCHAR *idx_type = NULL;
    TSK_TCHAR *db_file = NULL;
    TSK_TCHAR *lookup_file = NULL;
    unsigned int flags = 0;
    TSK_HDB_INFO *hdb_info;
    TSK_TCHAR **argv;
    bool create = false;
    bool addHash = false;

#ifdef TSK_WIN32
    // On Windows, get the wide arguments (mingw doesn't support wmain)
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if( argv == NULL) {    
        tsk_fprintf(stderr, "Error getting wide arguments\n");
        exit(1);
    }
#else
    argv = (TSK_TCHAR **)argv1;
#endif
    
    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = GETOPT(argc, argv, _TSK_T("cef:i:aqV"))) > 0) {
        switch (ch) {
        case _TSK_T('e'):
            flags |= TSK_HDB_FLAG_EXT;
            break;

        case _TSK_T('f'):
            lookup_file = OPTARG;
            break;

        case _TSK_T('i'):
            idx_type = OPTARG;
            break;

        case _TSK_T('c'):
            create = true;
            break;

        case _TSK_T('a'):
            addHash = true;
            break;

        case _TSK_T('q'):
            flags |= TSK_HDB_FLAG_QUICK;
            break;

        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);

        default:
            usage();
        }
    }
    
    if ((addHash) && ((idx_type != NULL) || (create))) {
        tsk_fprintf(stderr, "-a cannot be specified with -c or -i\n");
        usage();
    }

    if (OPTIND + 1 > argc) {
        tsk_fprintf(stderr,
                    "Error: You must provide the source hash database location\n");
        usage();
    }

    db_file = argv[OPTIND++];

    // Running in create mode (-c option). Make a new hash database and exit.
    if (create) {
        if (idx_type != NULL) {
            tsk_fprintf(stderr, "-c and -i cannot be specified at same time\n");
            usage();
        }
        
        TSK_TCHAR *ext = TSTRRCHR(db_file, _TSK_T('.'));    
        if ((NULL != ext) && (TSTRLEN(ext) >= 4) && (TSTRCMP(ext, _TSK_T(".kdb")) == 0)) {
            if (0 == tsk_hdb_create(db_file)) {
                tsk_fprintf(stdout, "New database %" PRIttocTSK" created\n", db_file);
                return 0;
            }
            else {
                tsk_fprintf(stderr, "Failed to create new database %" PRIttocTSK"\n", db_file);
                return 1;
            }        
        }
        else {
            tsk_fprintf(stderr, "New database path must end in .kdb extension\n");
            return 1;
        }
    }
        
    // Opening an existing database.    
    if ((hdb_info = tsk_hdb_open(db_file, TSK_HDB_OPEN_NONE)) == NULL) {
        tsk_error_print(stderr);
        return 1;
    }
    
    // Now that the database is open and its type is known, if running in add hashes mode (-a option)
    // see if it takes updates.
    if (addHash && !tsk_hdb_accepts_updates(hdb_info)) {
        tsk_fprintf(stderr, "-a option specified, but the specified database does not allow hashes to be added\n");
        usage();
    }

    // Running in indexing mode (-i option). Create an index file and exit.
    if (idx_type != NULL) {
        if (lookup_file != NULL) {
            tsk_fprintf(stderr, "'-f' flag can't be used with '-i'\n");
            usage();
        }

        if (flags & TSK_HDB_FLAG_QUICK) {
            tsk_fprintf(stderr, "'-q' flag can't be used with '-i'\n");
            usage();
        }

        if (flags & TSK_HDB_FLAG_EXT) {
            tsk_fprintf(stderr, "'-e' flag can't be used with '-i'\n");
            usage();
        }

        if (!tsk_hdb_uses_external_indexes(hdb_info)) {
            tsk_fprintf(stderr, "Database does not use external indexes, can't be used with '-i'\n");
        }

        if (tsk_hdb_is_idx_only(hdb_info)) {
            tsk_fprintf(stderr, "Database is index only, can be used for look ups, but can't be used with '-i'\n");
        }

        if (tsk_hdb_make_index(hdb_info, idx_type)) {
            tsk_error_print(stderr);
            tsk_hdb_close(hdb_info);
            return 1;
        }
        
        tsk_fprintf(stdout, "Index created\n");
        tsk_hdb_close(hdb_info);
        return 0;
    }

    /* Either lookup hash values or add them to DB.
     * Check if the values were passed on the command line or via a file 
     */
    if (OPTIND < argc) {

        if ((OPTIND + 1 < argc) && (flags & TSK_HDB_FLAG_QUICK)) {
            fprintf(stderr,
                    "Error: Only one hash can be given with quick option\n");
            usage();
        }

        if ((flags & TSK_HDB_FLAG_EXT) && (flags & TSK_HDB_FLAG_QUICK)) {
            fprintf(stderr, "'-e' flag can't be used with '-q'\n");
            usage();
        }

        if (lookup_file != NULL) {
            fprintf(stderr,
                    "Error: -f can't be used when hashes are also given\n");
            usage();
        }

        /* Loop through all provided hash values
         */
        while (OPTIND < argc) {
            char htmp[128];
            int i;
            int retval;

            // convert to char -- lazy way to deal with WCHARs..
            for (i = 0; i < 127 && argv[OPTIND][i] != '\0'; i++) {
                htmp[i] = (char) argv[OPTIND][i];
            }
            htmp[i] = '\0';

            if (addHash) {
                // Write a new hash to the database/index, if it's updateable
                //@todo support sha1 and sha2-256
                retval = tsk_hdb_add_entry(hdb_info, NULL, (const char *)htmp, NULL, NULL, NULL);
                if (retval == 1) {
                    printf("There was an error adding the hash.\n");
                    tsk_error_print(stderr);
                    return 1;
                }
                else if (retval == 0) {
                    printf("Hash %s added.\n", htmp);
                }
            }
            else {
                /* Perform lookup */
                retval = tsk_hdb_lookup_str(hdb_info, (const char *)htmp, 
                         (TSK_HDB_FLAG_ENUM)flags, lookup_act, NULL);
                if (retval == -1) {
                    tsk_error_print(stderr);
                    return 1;
                }
                if (flags & TSK_HDB_FLAG_QUICK) {
                    printf("%d\n", retval);
                }
                else if (retval == 0) {
                    print_notfound(htmp);
                }
            }
            OPTIND++;
        }
    }
    /* Hash were given from stdin or a file */
    else {
        char buf[100];

        /* If the file was specified, use that - otherwise stdin */
#ifdef TSK_WIN32
        HANDLE handle = NULL;
        if (lookup_file != NULL) {
            if ((handle = CreateFile(lookup_file, GENERIC_READ,
                                     FILE_SHARE_READ, 0, OPEN_EXISTING, 0,
                                     0)) == INVALID_HANDLE_VALUE) {
                TFPRINTF(stderr, _TSK_T("Error opening hash file: %s\n"),
                         lookup_file);
                exit(1);
            }
        }
        else {
            handle = GetStdHandle(STD_INPUT_HANDLE);
        }
#else
        FILE *handle = NULL;
        if (lookup_file != NULL) {
            handle = fopen(lookup_file, "r");
            if (!handle) {
                fprintf(stderr, "Error opening hash file: %s\n",
                        lookup_file);
                exit(1);
            }
        }
        else {
            handle = stdin;
        }
#endif

        while (1) {
            int retval;
            memset(buf, 0, 100);
#ifdef TSK_WIN32
            int done = 0;
            // win32 doesn't have a fgets equivalent, so we make an equivalent one
            for (int i = 0; i < 100; i++) {
                DWORD nread;

                if (FALSE == ReadFile(handle, &buf[i], (DWORD) 1, &nread, NULL)) {
                    done = 1;
                    break;
                }
                // skip the windows CR
                else if (buf[i] == '\r') {
                    buf[i] = '\0';
                    i--;
                    continue;
                }
                else if (buf[i] == '\n') {
                    break;
                }
            }
            
            if (done)
                break;
#else
            if (NULL == fgets(buf, 100, handle)) {
                break;
            }
#endif

            /* Remove the newline */
            buf[strlen(buf) - 1] = '\0';

            retval =
                tsk_hdb_lookup_str(hdb_info, (const char *)buf, 
                        (TSK_HDB_FLAG_ENUM)flags, lookup_act, NULL);
            if (retval == -1) {
                tsk_error_print(stderr);
                return 1;
            }
            if (flags & TSK_HDB_FLAG_QUICK) {
                printf("%d\n", retval);
                break;
            }
            else if (retval == 0) {
                print_notfound(buf);
            }
        }
        
#ifdef TSK_WIN32
        if (lookup_file != NULL)
            CloseHandle(handle);
#else
        if (lookup_file != NULL)
            fclose(handle);
#endif
        
    }

    tsk_hdb_close(hdb_info);
    return 0;
}
