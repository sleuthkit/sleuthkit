#ifndef BLOOMSET_H
#define BLOOMSET_H

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

#include "bloom.h"
#include <vector>
#include <assert.h>
#include <fcntl.h>

class bloomset_element {
    NSRLBloom *bloom;
public:
    enum Action {INCLUDE,EXCLUDE} action;
    int query(const unsigned char *hash) { return nsrl_bloom_query(bloom,hash); }
    bloomset_element(Action action,const char *fname){
	this->action = action;
	bloom = new NSRLBloom();
	bloom->open(fname,O_RDONLY);
    }
    ~bloomset_element(){
	delete bloom;
    }
};

class bloomset : public std::vector<bloomset_element *> {
public:
    // object is excluded if it is in an exclude bloom filter.
    // object is included if it is in an include bloom filter
    // if object is not present, if there are include filters it is excluded, otherwise it is included
    bool check_exclude(const unsigned char *hash){ // returns true if this should be excluded
	int include_count = 0;
	int exclude_count = 0;
	for(bloomset::const_iterator it = this->begin();
	    it != this->end();
	    it++){
	    switch((*it)->action){
	    case bloomset_element::INCLUDE:
		include_count++;
		if((*it)->query(hash)) return false; // do not exclude
		break;
	    case bloomset_element::EXCLUDE:
		exclude_count++;
		if((*it)->query(hash)) return true; // do exclude
		break;
	    default:
		assert(0);			// that's bad
	    }
	}
	if(include_count>0) return true;	// there were include filters, and this wasn't in it, so exclude
	return false;
    }
};

#endif



