/**
 * myglob.cpp:
 *
 * Globbing is not available on Windows, so this is a globbing implementation.
 */


#include "tsk3/tsk_tools_i.h"
//#include "config.h"
#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <ctype.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "myglob.h"

#include <iostream>
#include <fstream>

using namespace std;

myglob::myglob(const string &pattern)
{
    /* Build the regular expression from the pattern */
    string re;				// the regular expression

    re.push_back('^');			// beginning of string
    for(string::const_iterator it = pattern.begin(); it!=pattern.end(); it++){
	switch(*it){
	case '?': re.push_back('.'); break;
	case '.': re.append("[.]");  break;
	case '(': re.append("\\(");  break;
	case ')': re.append("\\)");  break;
	case '*': re.append(".*");   break;
	default:  re.push_back(*it); break;
	}
    }
    re.push_back('$');
    if(regcomp(&reg,re.c_str(),REG_EXTENDED|REG_ICASE)){
	std::cerr << "invalid regular expression: " << re << "\n";
	exit(1);
    }
}

myglob::~myglob()
{
    regfree(&reg);
}

bool myglob::match(const string &fname)
{
    regmatch_t pmatch[10];
    memset(pmatch,0,sizeof(pmatch));
    int res = regexec(&reg,fname.c_str(),10,pmatch,0);
    return (res==0);
}


