#include <assert.h>
#include <stdio.h>

class arecord {
public:
    arecord(int start,int len){
	this->start = start;
	this->len = len;
    }
    class arecord *before;
    class arecord *after;
    int start;
    int len;
};

class atree {
public:
    class arecord *root;
    atree(){
	root = 0;
    };
    void insert(arecord **where,int start,int len){
	printf("insert(%p,start=%d,len=%d)\n",where,start,len);

	if(len==0) return;		// nothing o inser

	/* If there is no node here, insert one. */
	if(*where == 0){
	    *where = new arecord(start,len);
	    return;
	}

	/* Have a more convenient reference to the current node */
	arecord &current = *(*where);

	/* If new node is contained by current, just return */
	if(current.start <= start && current.start+current.len >= start+len){
	    return;
	}

	/* If new node contains current, process before and after alone */
	if(start < current.start && start+len > current.start+current.len){
	    insert(where,start,current.start-start);
	    insert(where,current.start+current.len,(start+len)-(current.start+current.len));
	    return;
	}


	/* If new node contains the start point, just process the segment before the current start */
	if(start<current.start && start+len > current.start){
	    insert(where,start,(current.start-start));
	    return;
	}
	/* If new node contains the end point of the current node, just process the segment after the end */
	
	if(start<(current.start+current.len) && start+len > (current.start+current.len)){
	    insert(where,(current.start+current.len),start+len-(current.start+current.len));
	    return;
	}

	/* See if we can extend this node to the beginning */
	if(start+len == current.start){
	    current.start -= len;
	    current.len   += len;
	    return;
	}
	/* See if we can extend this node to the end */
	if(current.start + current.len == start){
	    current.len += len;
	    return;
	}

	/* See if new node goes before the current node */
	if(start < current.start){
	    insert( &current.before,start,len); // recurse to the left
	    return;
	}

	/* See if new node goes after the current node */
	if(current.start + current.len <= start){
	    insert( & current.after,start,len); // recurse to the left
	    return;
	}
	assert(0);			// shoudln't reach here
    }
    void insert(int start,int len){
	insert(&root,start,len);
    }
    void print(arecord &where,FILE *out){
	if(where.before) print(*where.before,out);
	fprintf(out,"%d-%d\n",where.start,where.start+where.len-1);
	if(where.after) print(*where.after,out);
    }
    void print(FILE *out){
	if(root) print(*root,out);
	printf("========\n");
    }
};


int main(int argc,char **argv)
{
    atree *a = new atree();

    a->insert(100,100);
    a->insert(50,100);
    a->print(stdout);

    a->insert(50,100);
    a->insert(100,100);
    a->print(stdout);


    a = new atree();
    a->insert(100,100);
    a->insert(50,200);
    a->print(stdout);

    a = new atree();
    a->insert(50,200);
    a->insert(100,100);
    a->print(stdout);
    return(0);
}
