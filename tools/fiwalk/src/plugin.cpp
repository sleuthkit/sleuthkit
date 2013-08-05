/**
 * Implements the fiwalk plugin API
 * the fiwalk plugin configuration file is a text file that contains multiple lines of:
 * <glob> (dgi|jvm) command
 *
 * <glob>   specifies which matching files should be called for the plugin; use * to call for
 *          for all files.
 *
 * dgi      means use the digitial forensics gateway interface; each plug-in is called
 *          with the filename on the command line to analyze, and the found terms are sent
 *	    to stdout as a series of name: value pairs.
 *
 * command  the command to run.
 *
 * Future additions:
 * Put the temp files on a ram drive, to make it faster to access them.
 * Have a way of emitting XML.
 *          
 */

#include "tsk/tsk_tools_i.h"

#define __DARWIN_64_BIT_INO_T 1		

#include <string.h>
#include <stdlib.h>

#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef TSK_WIN32
#include <direct.h>
#define popen	_popen
#define pclose	_pclose
#else
#include <dirent.h>
#endif

#include <algorithm>
#include <string>
#include <iostream>
#include <string>
#include <vector>

#include <tsk/libtsk.h>

#include "fiwalk.h"
#include "plugin.h"
#include "arff.h"

#ifdef _MSC_VER
/* TK: A class that uses Microsoft's regex class */
#else
extern "C" {
#include <regex.h>
}
#endif

class myglob {
public:
    regex_t reg;

    myglob(const std::string &pattern){
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
    };
    bool match(const std::string &fname){
	regmatch_t pmatch[10];
	memset(pmatch,0,sizeof(pmatch));
	int res = regexec(&reg,fname.c_str(),10,pmatch,0);
	return (res==0);
    };
    ~myglob(){
	regfree(&reg);
    };
};


/** describes each plugin */
class plugins {
public:;
    myglob *glob;
    string pattern;		// what we want
    string method;
    string path;
    plugins():glob(0){
    }
    plugins(string pattern,string method,string path){
	this->pattern = pattern;
	this->glob = new myglob(pattern.c_str());
	this->method = method;
	this->path = path;
	
    }
    ~plugins() {
	if(glob){
	    delete glob;
	    glob=0;
	}
    }
};

vector<class plugins *> plugin_list;

static bool all_whitespace(const char *buf)
{
    while(*buf){
	if(!isspace(*buf)) return false;
	buf++;
    }
    return true;
}

/** Return TRUE if the FNAME requires plugin processing */
const plugins *current_plugin = 0;
bool plugin_match(const std::string &fname)
{
    for(vector<class plugins *>::const_iterator i = plugin_list.begin();
	i != plugin_list.end();
	i++){
	if( (*i)->glob->match(fname)){
	    current_plugin = (*i);
	    return true;
	}
    }
    return false;
}

/** Called by fiwalk main for each extracted file.
 * the file is created in the /tmp directory.
 * The plugin outputs a set of name: value pairs on standard output.
 * This code finds each of those name: value pairs and calls file_info(name,value)
 * for each. Names and values are passed to file_info as strings.
 */
void plugin_process(const std::string &fname)
{
    comment("plugin_process",fname.c_str());
    static bool first = true;
    static regex_t ncv;
    if(first){
	if(regcomp(&ncv,"([-a-zA-Z0-9_]+): +(.*)",REG_EXTENDED)) err(1,"regcomp");
	first = 0;
    }

    if(current_plugin->method=="dgi"){
	string cmd = current_plugin->path + " " + fname;
	FILE *f = popen(cmd.c_str(),"r");
	if(!f) err(1,"fopen: %s",cmd.c_str());
	char linebuf[65536];
	while (fgets(linebuf,sizeof(linebuf),f)){
	    char *cc = strchr(linebuf,'\n');
	    if(cc){		// we found an end-of-line
		*cc = '\000';
	    }
	    else {
		// line was longer than our buffer; why aren't we using c++?
		// scan to the newline
		while(!feof(f)){
		    int ch = fgetc(f);
		    if(ch<0 || ch=='\n') break;
		}
	    }
	    
	    /* process name: value pairs */
	    regmatch_t pmatch[4];
	    memset(pmatch,0,sizeof(pmatch));
	    if(regexec(&ncv,linebuf,4,pmatch,0)){
		fprintf(stderr,"*** FILE: %s   line: %u\n",__FILE__,__LINE__);
		fprintf(stderr,"*** plugin %s returned: '%s'\n", current_plugin->path.c_str(),linebuf);
		fprintf(stderr,"*** original command line: %s\n",cmd.c_str());
		fprintf(stderr,"*** %s will not be deleted.\n",fname.c_str());
		exit(1);
	    }
	    linebuf[pmatch[1].rm_eo] = 0;
	    linebuf[pmatch[2].rm_eo] = 0;
	    char *name = linebuf+pmatch[1].rm_so;
	    char *value = linebuf+pmatch[2].rm_so;

	    /* clean any characters in the name */
	    for(char *cc=name;*cc;cc++){
          if (!isalpha(*cc)) *cc='_';
	    }

	    file_info(name,value);	// report each identified name & value
	}
	pclose(f);
	return;
    }
}


void config_read(const char *fname)
{
    /* make sure the glob function works */
    myglob *g1 = new myglob("*.jpeg");
    myglob *g2 = new myglob("*.jpg");

    assert(g1->match("file.jpeg")==true);
    assert(g1->match("file.jpg")==false);

    assert(g2->match("file.jpeg")==false);
    assert(g2->match("file.jpg")==true);
    delete g1;
    delete g2;

    // Compile the regular expression we will use;
    // Unfortunately the POSIX regex has no support for \s
    regex_t r;
    if(regcomp(&r,"([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^\t\r\n]+)",REG_EXTENDED)) err(1,"regcomp"); 
    FILE *f = fopen(fname,"r");
    if(!f) err(1,"%s",fname);
    char linebuf[1024];
    int linenumber = 0;
    while(fgets(linebuf,sizeof(linebuf),f)){
	linenumber++;
	char *cc = strchr(linebuf,'#');
	if(cc) *cc = 0;			// terminate #'s

	/* if the line all whitespace ignore it */
	if(all_whitespace(linebuf)) continue;

	/* parse the line */
	regmatch_t pmatch[10];
	memset(pmatch,0,sizeof(pmatch));
	int res = regexec(&r,linebuf,10,pmatch,0);
	if(res){
	    fprintf(stderr,"Error in configuration file line %d: %s\n",linenumber,linebuf);
	    exit(1);
	}
	linebuf[pmatch[1].rm_eo] = 0;
	linebuf[pmatch[2].rm_eo] = 0;
	linebuf[pmatch[3].rm_eo] = 0;

	class plugins *plug = new plugins(linebuf+pmatch[1].rm_so, linebuf+pmatch[2].rm_so, linebuf+pmatch[3].rm_so);
	plug->glob = new myglob(plug->pattern.c_str());
	comment("pattern: %s  method: %s  path: %s",plug->pattern.c_str(),plug->method.c_str(),plug->path.c_str());
	plugin_list.push_back(plug);
    }
    fclose(f);
    regfree(&r);
}
