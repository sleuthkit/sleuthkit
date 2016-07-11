/*
 *
 * arff generator class
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

#include "tsk/tsk_tools_i.h"
#include "fiwalk.h"
#include <sys/types.h>

#ifdef _MSC_VER
#include <winsock.h>
#include <time.h>
#else
#include <sys/time.h>
#endif

#ifdef _MSC_VER
  #include "regex.h"  //use regex in src tree
#else
  extern "C" {
    #include <regex.h>
  }
#endif

#include "arff.h"

using namespace std;

#define REGEX_MATCH 0

static bool debug=0;

static bool has_non_numeric(const string &s)
{
    for(string::const_iterator it = s.begin(); it!=s.end();it++){
	if(isdigit((*it))==0 && (*it)!='.' && (*it)!='-' && (*it)!='+') return true; // it has a non-numeric
	if(it!=s.begin()){
	    if (((*it)=='-' )||(*it)=='+') return true; // + or - at a position other than first
	}
    }
    return false;
}

/* Is a string really a date? We would like this to be fast...
 * It should probably be done with regular expressions...
 */
bool arff::is_weka_date(const string &s)
{
    if(isdigit(s[0]) && isdigit(s[1]) && isdigit(s[2]) && isdigit(s[3]) && s[4]=='-' &&
       isdigit(s[5]) && isdigit(s[6]) && s[7]=='-' &&
       isdigit(s[8]) && isdigit(s[9])  &&
       s[10]==' ' &&
       isdigit(s[11]) && isdigit(s[12]) && s[13]==':' &&       
       isdigit(s[14]) && isdigit(s[15]) && s[16]==':' &&       
       isdigit(s[17]) && isdigit(s[17]) && s.size()==19) return true;
    return false;
}

/* microsoft metadata date format: YYYY-MM-DDTHH:MM:SSZ */
bool arff::is_msword_date(const string &s) 
{
  //regex_t objects hold the regular expressions
  static regex_t msdoc_date;

  regcomp(&msdoc_date, "[0-9]{4}-[01]{1}[0-9]{1}-[0123]{1}[0-9]{1}T[012]{1}[0-9]{1}:[0-5]{1}[0-9]{1}:[0-5]{1}[0-9]{1}Z", REG_EXTENDED|REG_ICASE);
  
  return regexec(&msdoc_date, s.c_str(), 0, NULL, 0)==REGEX_MATCH;

}

/* exif metadate date format: YYYY:MM:DD HH:MM:SS */
bool arff::is_exif_date(const string &s) 
{
  //regex_t objects hold the regular expressions
  static regex_t exif_date;

  regcomp(&exif_date, "[0-9]{4}:[01]{1}[0-9]{1}:[0123]{1}[0-9]{1} [012]{1}[0-9]{1}:[0-5]{1}[0-9]{1}:[0-5]{1}[0-9]{1}", REG_EXTENDED|REG_ICASE);

  return regexec(&exif_date, s.c_str(), 0, NULL, 0)==REGEX_MATCH;

}

/* checks to see if input string is a recognized date format-- one of
 * either: weka's own time format: YYYY-MM-DD HH:MM:SS
 * YYYY-MM-DDTHH:MM_SSZ (miscrosoft word meta data date format)
 * YYYY:MM:DD HH:MM_SSZ (exif meta data date format)
 */

bool arff::is_recognized_date_format(const string &s)
{
  if (is_msword_date(s) || is_exif_date(s) || is_weka_date(s))
    return true;
  else return false;
}

/* Converts recognized date formats from strings into weka specific
 * date strings, so that they can be processed by weka as proper
 * dates.
 * weka date format: "YYYY-MM-DD HH:MM:SS".
 * Possible edge case: date but no time?
 */
string arff::make_weka_date(const string &s)
{
  /* a date-type attribute will usually have at least some (if not
     many) empty values (represented by the "?"). */
  if(s=="?") return "?";

  string wekadate = "";
  
  wekadate = s;
  if (is_msword_date(s)) { 
    /* convert to weka date format by replacing the T with a space 
       and removing the trailing Z */
    wekadate.replace(10,1," "); //replace 1 char starting at index 10 with a space
    wekadate.erase(19); //remove trailing Z. 
  }
  else if (is_exif_date(s)) {
    /* convert to weka date format by replacing the colons with hyphens in the date */
    wekadate.replace(4,1,"-");
    wekadate.replace(7,1,"-");
  }
  else {
    fprintf(stderr,"\nmake_weka_date('%s')\n",s.c_str());
    fprintf(stderr, "no recognized date format found. arff date conversion failed.");
    exit(1);
  }

  if (wekadate.length() != 19){
    fprintf(stderr, "date string is wrong length. it was probably malformed.\n");
    exit(1);
  }

  return wekadate;
}

/****************************************************************/
void arff::add_comment(string comment)
{
    comments.push_back(comment);
}

bool arff::has_attribute(const string &name) const
{
    for(unsigned int i=0;i<attributeTypes.size();i++){
	if(attributeNames[i]==name) return true;
    }
    return false;
}

/**
 * If the attribut hasn't already been given a type,
 * add a type.
 */

void arff::add_attribute(string name,int code)
{

    for(unsigned int i=0;i<attributeTypes.size();i++){
	if(attributeNames[i]==name){
	    return;			// older types dominate newer ones;
	}
    }
    attributeTypes.push_back(code);
    attributeNames.push_back(name);
    attributeCodes[name] = attributeNames.size()-1;
}

/**
 * Create a new row in the ARFF output file
 */
void arff::new_row()
{
    values.push_back(new valueMapT);
}

/**
 * The basic add_value:
 * First check to see if the attribute has been registered.
 * If it has not been registered, register it as a string.
 * Then add the (attribute,value) pair to the sparse matrix.
 */
void arff::add_value(string name,const string &value)
{
    if(debug) fprintf(stderr,"add_value(name='%s' value='%s')\n",name.c_str(),value.c_str());

    // If type doesn't exist, create it and make it a STRING
    if(attributeCodes.find(name)==attributeCodes.end()){
	add_attribute(name,STRING);
    }

    int code = attributeCodes[name];
    (*values.back())[code] = value;
}


/**
 * Add a value that is a date/time value.
 * Format the value the way that WEKA expects it, and add it as a string.
 */
void arff::add_valuet(string name,time_t t)
{
#ifdef _MSC_VER
#define TM_FORMAT "%Y-%m-%d %H:%M:%S"
#else
#define TM_FORMAT "%F %T"
#endif

    if(t==0) return;			// ignore invalid dates

    // If type doesn't exist, create it and make it a STRING
    if(attributeCodes.find(name)==attributeCodes.end()){
	add_attribute(name,STRING);
    }
    int code = attributeCodes[name];
    char buf[64];
    strftime(buf,sizeof(buf),TM_FORMAT,gmtime(&t));
    (*values.back())[code] = buf;
}


/**
 * Add a value that is a number.
 */
void arff::add_value(string name,int64_t value)
{
    // If type doesn't exist, create it and make it a STRING
    if(attributeCodes.find(name)==attributeCodes.end()){
	add_attribute(name,STRING);
    }
    int code = attributeCodes[name];
    int type = attributeTypes[code];
    time_t valuet = value;

    char buf[64];
    switch(type){
    case DATE:
	strftime(buf,sizeof(buf),TM_FORMAT,gmtime((time_t *)&valuet));
	break;
    default:
	sprintf(buf,"%" PRIu64,value);
	break;
    }
    (*values.back())[code] = buf;
}

/****************************************************************/

int arff::attributeCol(const string &attributeName) const
{
    for(unsigned int i=0;i<attributeNames.size();i++){
	if(attributeNames[i]==attributeName) return i;
    }
    return -1;
}

/* Scan the values we have for an attribute and return true if it always missing or numeric. */
bool arff::attributeAlwaysNumeric(const string &attributeName) const
{
    int col = attributeCol(attributeName);
    for(vector<valueMapT *>::const_iterator row = values.begin(); row!= values.end(); row++){
	valueMapT::const_iterator k = (*row)->find(col); // find the row we are looking for
	if(k==(*row)->end()) continue;		   // no value
	const string &val = (*k).second.c_str();	   // no need to copy
	if(has_non_numeric(val)) return false;
    }
    return true;
}


bool arff::attributeAlwaysDate(const string &attributeName) const
{
    int col = attributeCol(attributeName);
    for(vector<valueMapT *>::const_iterator row = values.begin(); row!= values.end(); row++){
	valueMapT::const_iterator k = (*row)->find(col); // find the row we are looking for
	if(k==(*row)->end()) continue;		   // no value
	const string &val = (*k).second.c_str();	   // no need to copy
	if(is_recognized_date_format(val)==false) return false;
    }
    return true;
}

/** return true if a string needs quoting */
bool arff::needs_quoting(const string &str){
    for(string::const_iterator it=str.begin();it!=str.end();it++){
	if ((*it)<32) return true;
	switch((*it)){
	case ' ':
	case '{':
	case '}':
	case ',':
	case '\t':
	    return true;
	}
    }
    return false;
}

void arff::write_row(FILE *out,const valueMapT &row)
{
    for(unsigned int i=0;i<attributeNames.size();i++){
	valueMapT::const_iterator k = row.find(i); // find the row we are looking for
	string val("?");		// default value - no value
	
	if(k!=row.end()){	// if we have data
	    val = (*k).second;
	    
	    /* if this attribute is type DATE and the val is not in weak date format,
	     * turn it into weka date format
	     */
	    if(attributeTypes[i]==DATE && is_weka_date(val)==false){		  
		val = make_weka_date(val);
	    }
	    
	    /* Change any quotes to spaces */
	    for(unsigned int j=0;j<val.size();j++){
		if(val[j]=='"') val[j]=' ';
		if(val[j]=='\'') val[j]=' ';
	    }
	    /* If there are any characters to quote, then quote it. */
	    if(needs_quoting(val)){
		/* Make sure that the last character is not a \ */
		int valend = val.length()-1;
		if(val[valend] == '\\') val.push_back(' ');
		val = "\"" + val + "\""; // quote it
	    }
	}
	if(val.size()==0) val="?";	// put back the ?
	if(i>0) fprintf(out,", ");
	fprintf(out,"%s",val.c_str());
    }
    fprintf(out,"\n");
}

void arff::write()
{
    /* Before we generate the output, see if any of the string
     * attributes always have numeric (or date) values.  If so, we'll
     * change them into numeric (or date) values...  note that this
     * only checks if the values are always numeric (or date) when
     * they are present-- ie, if some records have missing values for
     * this attribute it does not disqualify them.
     */
    for(unsigned int i=0;i<attributeNames.size();i++){
	if(attributeTypes[i]==STRING && attributeAlwaysNumeric(attributeNames[i])){
	    attributeTypes[i]=NUMERIC;
	}
	if(attributeTypes[i]==STRING && attributeAlwaysDate(attributeNames[i])){	 
	  attributeTypes[i]=DATE;
	}
    }

    for(vector<string>::const_iterator i = comments.begin();
	i!= comments.end();
	i++){
	fprintf(outfile,"%% %s\n",i->c_str());
    }
    fprintf(outfile,"\n");
    fprintf(outfile,"@RELATION %s\n",relation.c_str());
    fprintf(outfile,"\n");
    
    /* Write out the attributes */
    for(unsigned int i=0;i<attributeNames.size();i++){
	string name = attributeNames[i];

	/* Turn the spaces into underbars */
	for(string::iterator j = name.begin();j!=name.end();j++){
	    if(*j == ' ') *j = '_';
	}
	switch(attributeTypes[i]){
	case NUMERIC:
	    fprintf(outfile,"@ATTRIBUTE %s NUMERIC\n",name.c_str());
	    break;
	case DATE:
	    fprintf(outfile,"@ATTRIBUTE %s date \"yyyy-MM-dd HH:mm:ss\"\n",name.c_str());
	    break;
	case STRING:
	    fprintf(outfile,"@ATTRIBUTE %s string\n",name.c_str());
	    break;
	default:
	    assert(0);
	}
    }

    /* Write out the data */
    fprintf(outfile,"\n@DATA\n\n");
    for(vector<valueMapT *>::const_iterator row = values.begin();
	row!= values.end();
	row++){
	write_row(outfile,**row);
    }
    fflush(outfile);
}

