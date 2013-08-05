/*
 * The Sleuth Kit 
 */
// XGetopt.cpp  Version 1.2
//
// Author:  Hans Dietrich
//          hdietrich2@hotmail.com
//
// Description:
//     XGetopt.cpp implements getopt(), a function to parse command lines.
//
// History
//     Version 1.2 - 2003 May 17
//     - Added Unicode support
//
//     Version 1.1 - 2002 March 10
//     - Added example to XGetopt.cpp module header 
//
// This software is released into the public domain.
// You are free to use it in any way you like.
//
// This software is provided "as is" with no expressed
// or implied warranty.  I accept no liability for any
// damage or loss of business that this software may cause.
//
///////////////////////////////////////////////////////////////////////////////

/** \file XGetopt.c
 * Parses arguments for win32 programs -- written by Hans Dietrich.
 */

#include "tsk_base_i.h"
#ifdef TSK_WIN32
///////////////////////////////////////////////////////////////////////////////
// if you are using precompiled headers then include this line:
//#include "stdafx.h"
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
// if you are not using precompiled headers then include these lines:
#include <wchar.h>
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
//
//  X G e t o p t . c p p
//
//
//  NAME
//       getopt -- parse command line options
//
//  SYNOPSIS
//       int getopt(int argc, TSK_TCHAR *argv[], TSK_TCHAR *optstring)
//
//       extern TSK_TCHAR *optarg;
//       extern int optind;
//
//  DESCRIPTION
//       The getopt() function parses the command line arguments. Its
//       arguments argc and argv are the argument count and array as
//       passed into the application on program invocation.  In the case
//       of Visual C++ programs, argc and argv are available via the
//       variables __argc and __argv (double underscores), respectively.
//       getopt returns the next option letter in argv that matches a
//       letter in optstring.  (Note:  Unicode programs should use
//       __targv instead of __argv.  Also, all character and string
//       literals should be enclosed in _TSK_T( ) ).
//
//       optstring is a string of recognized option letters;  if a letter
//       is followed by a colon, the option is expected to have an argument
//       that may or may not be separated from it by white space.  optarg
//       is set to point to the start of the option argument on return from
//       getopt.
//
//       Option letters may be combined, e.g., "-ab" is equivalent to
//       "-a -b".  Option letters are case sensitive.
//
//       getopt places in the external variable optind the argv index
//       of the next argument to be processed.  optind is initialized
//       to 0 before the first call to getopt.
//
//       When all options have been processed (i.e., up to the first
//       non-option argument), getopt returns EOF, optarg will point
//       to the argument, and optind will be set to the argv index of
//       the argument.  If there are no non-option arguments, optarg
//       will be set to NULL.
//
//       The special option "--" may be used to delimit the end of the
//       options;  EOF will be returned, and "--" (and everything after it)
//       will be skipped.
//
//  RETURN VALUE
//       For option letters contained in the string optstring, getopt
//       will return the option letter.  getopt returns a question mark (?)
//       when it encounters an option letter not included in optstring.
//       EOF is returned when processing is finished.
//
//  BUGS
//       1)  Long options are not supported.
//       2)  The GNU double-colon extension is not supported.
//       3)  The environment variable POSIXLY_CORRECT is not supported.
//       4)  The + syntax is not supported.
//       5)  The automatic permutation of arguments is not supported.
//       6)  This implementation of getopt() returns EOF if an error is
//           encountered, instead of -1 as the latest standard requires.
//
//  EXAMPLE
//       BOOL CMyApp::ProcessCommandLine(int argc, TSK_TCHAR *argv[])
//       {
//           int c;
//
//           while ((c = getopt(argc, argv, _TSK_T("aBn:"))) != EOF)
//           {
//               switch (c)
//               {
//                   case _TSK_T('a'):
//                       TRACE(_TSK_T("option a\n"));
//                       //
//                       // set some flag here
//                       //
//                       break;
//
//                   case _TSK_T('B'):
//                       TRACE( _TSK_T("option B\n"));
//                       //
//                       // set some other flag here
//                       //
//                       break;
//
//                   case _TSK_T('n'):
//                       TRACE(_TSK_T("option n: value=%d\n"), atoi(optarg));
//                       //
//                       // do something with value here
//                       //
//                       break;
//
//                   case _TSK_T('?'):
//                       TRACE(_TSK_T("ERROR: illegal option %s\n"), argv[optind-1]);
//                       return FALSE;
//                       break;
//
//                   default:
//                       TRACE(_TSK_T("WARNING: no handler for option %c\n"), c);
//                       return FALSE;
//                       break;
//               }
//           }
//           //
//           // check for non-option args here
//           //
//           return TRUE;
//       }
//
///////////////////////////////////////////////////////////////////////////////

TSK_TCHAR *tsk_optarg;          // global argument pointer
int tsk_optind = 0;             // global argv index

int
tsk_getopt(int argc, TSK_TCHAR * const argv[], const TSK_TCHAR * optstring)
{
    static TSK_TCHAR *next = NULL;
    TSK_TCHAR c, *cp;
    if (tsk_optind == 0)
        next = NULL;

    tsk_optarg = NULL;

    if (next == NULL || *next == _TSK_T('\0')) {
        if (tsk_optind == 0)
            tsk_optind++;

        if (tsk_optind >= argc || argv[tsk_optind][0] != _TSK_T('-')
            || argv[tsk_optind][1] == _TSK_T('\0')) {
            tsk_optarg = NULL;
            if (tsk_optind < argc)
                tsk_optarg = argv[tsk_optind];
            return EOF;
        }

        if (TSTRCMP(argv[tsk_optind], _TSK_T("--")) == 0) {
            tsk_optind++;
            tsk_optarg = NULL;
            if (tsk_optind < argc)
                tsk_optarg = argv[tsk_optind];
            return EOF;
        }

        next = argv[tsk_optind];
        next++;                 // skip past -
        tsk_optind++;
    }

    c = *next++;
    cp = (TSK_TCHAR *) TSTRCHR(optstring, c);

    if (cp == NULL || c == _TSK_T(':'))
        return _TSK_T('?');

    cp++;
    if (*cp == _TSK_T(':')) {
        if (*next != _TSK_T('\0')) {
            tsk_optarg = next;
            next = NULL;
        }
        else if (tsk_optind < argc) {
            tsk_optarg = argv[tsk_optind];
            tsk_optind++;
        }
        else {
            return _TSK_T('?');
        }
    }

    return c;
}
#endif
