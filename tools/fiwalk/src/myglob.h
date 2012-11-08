/*
 * my glob routines.
 *
 * A nice, friendly C++ class that uses regular expressions, not the glob mechanisms
 */

#ifndef MYGLOB_H
#define MYGLOB_H

#ifdef _MSC_VER
#include "regex.h"  //use regex in src tree
#else
extern "C" {
#include <regex.h>
}
#endif

#include <string>

class myglob {
public:
    regex_t reg;

    myglob(const std::string &pattern);
    bool match(const std::string &fname);
    ~myglob();
    
};

#endif
