/* 
* Author: Taha Ebrahim @Taha-Ebrahim
* Header file for tsk_tempfile.
*/
#ifndef _TSK_TEMPFILE_H
#define _TSK_TEMPFILE_H

#include <stdio.h>
#include <string>

// Creates a temporary file for use in testing.
FILE* tsk_make_tempfile();

// Creates a named temporary file for use in testing, and stores the path in `out_path`.
FILE* tsk_make_named_tempfile(std::string* out_path);

#endif // _TSK_TEMPFILE_H