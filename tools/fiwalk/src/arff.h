#ifndef ARFF_H
#define ARFF_H

/** The arff class controls the generation of ARFF output files.
 * For each attribute, add_attribute() can be called to specify the attribute type.
 * If no attribute type is specified, the default is string.
 *
 * Before the file is written out, each attribute column is scanned.
 * If the column is type STRING but all of the strings are really numbers,
 * the column type is changed to NUMERIC.
 *
 * If the column type is STRING but all of the strings are really dates,
 * the colum type is changed to DATE
 */

/*
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
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "outfile.h"

using namespace std;
#include <vector>
#include <stdlib.h>

class arff  {
    bool attributeAlwaysNumeric(const string &s) const;
    bool attributeAlwaysDate(const string &s) const;
    FILE *outfile;
public:
    static bool needs_quoting(const string &str);
    static bool is_weka_date(const string &s); //  true if is weka date/time format
    static bool is_msword_date(const string &s);
    static bool is_exif_date(const string &s);
    static bool is_recognized_date_format(const string &s); // true if is in any recognized date/time format
    static string to_weka_date(const string &s); // transforms non-weka dates to weka dates
    static string make_weka_date(const string &s);
    enum type {
	NUMERIC=1,
	NOMINAL=2,
	STRING=3,
	DATE=4
    };
    typedef std::map<string,int> attributeMapT;
    vector<string> attributeNames;	// list of all the attributes we have encountered
    vector<int>    attributeTypes;	// each attributes type, using the type enum above
    attributeMapT  attributeCodes;	//
	
    typedef std::map<int,string> valueMapT; // attribute number -> value

    vector<string>comments;		// ARFF 
    string relation;			// name of the relation
    vector<valueMapT *>values;		// each element of the vector is an ARFF row

    arff(string relation_name) {
	relation = relation_name;
    };
    void set_outfile(FILE *file) { outfile = file;}
    void set_outfile(string fn)  { outfile = fopen(fn.c_str(),"w"); if(!outfile){perror(fn.c_str());exit(1);} }
    void write_row(FILE *out,const valueMapT &row);
    void write();
    void add_comment(string comment);	
    void add_attribute(string name,int type); // allows specification of an attribute type
    void add_value(string name,int64_t number); // adds a numeric name/value
    void add_value(string name,const string &value); // adds a string name/value
    void add_valuet(string name,time_t t);
    bool has_attribute(const string &name) const; // returns true if attribute already named
    int  attributeCol(const string &attributeName) const; // returns attribute row
    void new_row();				// go to the next row
};

#endif
