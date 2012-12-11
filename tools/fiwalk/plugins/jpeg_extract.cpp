/*
 * jpeg DGI:
 *
 * build a jpeg extractor using the exif library.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc,char **argv)
{
    char cmdbuf[1024];			// command buffer
    char linebuf[1024];


    if(argc!=2){
	fprintf(stderr,"usage: %s <filename>",argv[0]);
	exit(1);
    }
    sprintf(cmdbuf,"exif -m %s 2>/dev/null",argv[1]);
    FILE *f = popen(cmdbuf,"r");
    if(!f) perror(cmdbuf);

    /* the exif -m command will give us lines of output, tab delimited.
     * For DGI output we want names: values
     */
    while(fgets(linebuf,sizeof(linebuf),f)){
	/* Fix known errors in formatting */
	if(strncmp(linebuf,"Date and Time",13)==0){
	    char *ds = strchr(linebuf,'\t');
	    if(ds && ds[5]==':' && ds[8]==':'){
		ds[5]='-';
		ds[8]='-';
	    }
	}

	bool before = true;
	for(char *cc=linebuf;*cc;*cc++){ // change ' '->'_" and '\t'->':' until we find the \t
	    if(before){
		switch(*cc){
		case ' ': putchar('-');break;
		case ':': putchar('-');break;
		case '(': putchar('-');break;
		case ')': putchar('-');break;
		case '\t': putchar(':');putchar(' ');before=false;break;
		default: putchar(*cc);break;
		}
	    }
	    else {
		putchar(*cc);
	    }
	}
    }
    pclose(f);
    return(0);
}
