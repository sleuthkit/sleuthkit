/*
 * my glob routines.
 *
 * A nice, friendly C++ class that uses regular expressions, not the glob mechanisms
 */

#ifndef MYGLOB_H
#define MYGLOB_H

extern "C" {
#include <regex.h>
}

#include <string>

class myglob {
public:
    regex_t reg;

    myglob(const std::string &pattern);
    bool match(const std::string &fname);
    ~myglob();
    
};

#endif
