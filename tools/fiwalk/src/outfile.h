/*
 * output file framework for ARFF/XML/TEXT
 *
 *
 * The software provided here is released by the Naval Postgraduate
 * School, an agency of the U.S. Department of Navy.  The software
 * bears no warranty, either expressed or implied. NPS does not assume
 * legal liability nor responsibility for a User's use of the software
 * or the results of such use.
 *
 * Please note that within the United States, copyright protection,
 * under Section 105 of the United States Code, Title 17, is not
 * available for any work of the United States Government and/or for
 * any works created by United States Government employees. User
 * acknowledges that this software contains work which was created by
 * NPS government employees and is therefore in the public domain and
 * not subject to copyright.
 */

#ifndef OUTFILE_H
#define OUTFILE_H

#include <string>
#include <map>
#include <stdio.h>

using namespace std;

class outfile {
    string outfile_name;			// final output file
    FILE *tempfile;				// temporary file
public:
    outfile(const string &filename){};
    virtual ~outfile(){};
    virtual bool needs_tempfile(){return false;}
    virtual void add_comment(const string &comment) = 0;
    virtual void add_value(const string &name,int64_t value) = 0;
    virtual void add_value(const string &name,const string &value) =0;
    virtual void add_valuet(const string &name,time_t t) = 0;
    virtual void new_row() = 0;
    virtual void write() = 0;
};

#endif
