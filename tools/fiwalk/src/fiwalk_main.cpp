/**
 * fiwalk.cpp:
 * File and Inode Walk.
 *
 * This application uses SleuthKit to generate a report of all of the files
 * and orphaned inodes found in a disk image. It can optionally compute the
 * MD5 of any objects, save those objects into a directory, or both.
 *
 * Algorithm:
 * 1 - Find all of the partitions on the disk.
 * 2 - For each partition, walk the files.
 * 3 - For each file, print the requested information.
 * 4 - For each partition, walk the indoes
 * 5 - For each inode, print the requested information.
 *
 * @author Simson Garfinkel
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

/* config.h must be first */
#include "tsk/tsk_tools_i.h"

#include <stdio.h>
#include "fiwalk.h"

void print_version()
{
    printf("SleuthKit Version: %s\n",tsk_version_get_str());
#ifdef HAVE_LIBAFFLIB
    printf("AFFLIB Version:    %s\n",af_version());
#else
    printf("*** NO AFFLIB SUPPORT ***\n");
#endif
#ifdef HAVE_LIBEWF
    printf("LIBEWF Version:    %s\n",libewf_get_version());
#else
    printf("*** NO LIBEWF SUPPORT ***\n");
#endif
}

#ifdef TSK_WIN32

static int convert(TSK_TCHAR *OPTARG, char **_opt_arg)
{
    char *opt_arg=*_opt_arg;
    char *temp = NULL;
    int arg_len = TSTRLEN(OPTARG);
    int ret_val = 0;

    opt_arg=(char *)tsk_malloc(TSTRLEN(OPTARG)+2);
    temp=opt_arg;
    ret_val =
        tsk_UTF16toUTF8(TSK_LIT_ENDIAN,
			(const UTF16 **) &OPTARG, (UTF16 *)(OPTARG+arg_len+1),
			(UTF8 **)&temp, (UTF8 *)(temp+arg_len+2), TSKlenientConversion);
    if (ret_val)
    {
        printf("Conversion Error ret_val: %d\n", ret_val);
        return ret_val;
    }
    *_opt_arg=opt_arg;
    return 0;
}
#endif

void usage(fiwalk &o)
{
    printf("usage: fiwalk [options] iso-name\n");
    printf("Default behavior: Just print the file system statistics and exit.\n");
    printf("options:\n");
    printf("    -c config.txt   read config.txt for metadata extraction tools\n");
    printf("    -C nn           only process nn files, then do a clean exit\n");

    printf("\n");
    printf("include/exclude parameters; may be repeated. \n");
    printf("    -n pattern  = only match files for which the filename matches\n");
    printf("                  the pattern.\n");
    printf("              example: -n .jpeg -n .jpg will find all JPEG files\n");
    printf("              Case is ignored. Will not match orphan files.\n");
    printf("    ");
    printf("\n");
    printf("Ways to make this program run faster:\n");
    printf("    -I ignore NTFS system files\n");
    printf("    -g just report the file objects - don't get the data\n");
    printf("    -O only walk allocated files\n");
    printf("    -b do not report byte runs if data not accessed\n");
    printf("    -z do not calculate MD5 or SHA1 values\n");
    printf("    -Gnn - Only process the contents of files smaller than nn gigabytes (default %d)\n", o.opt_maxgig);
    printf("           (Specify -G0 to remove space restrictions)\n");

    printf("\n");
    printf("Ways to make this program run slower:\n");
    printf("    -M = Report MD5 for each file (default on)\n");
    printf("    -1 = Report SHA1 for each file (default on)\n");
    printf("    -S nnnn = Perform sector hashes every nnnn bytes\n");
#ifdef HAVE_LIBMAGIC
    printf("    -f = Enable LIBMAGIC (disabled by default)");
#else
    printf("    -f = Report the output of the 'file' command for each\n");
#endif
    //printf("Full content options:\n");
    //printf("    -s <dir> = Save all recovered files to <dir>\n");
    printf("\n");
    printf("Output options:\n");
    printf("    -m = Output in SleuthKit 'Body file' format\n");
    printf("    -A<file> = ARFF output to <file>\n");
    printf("    -X<file> = XML output to a <file> (full DTD)\n");
    printf("         -X0 = Write output to filename.xml\n");
    printf("    -Y       = Do not include <creator> or <usage> DFXML sections (things that can change)\n");
    printf("    -Z       = zap (erase) the output file\n");
    printf("    -x       = XML output to stdout (no DTD)\n");
    printf("    -T<file> = Walkfile output to <file>\n");
    printf("    -a <audit.txt> = Read the scalpel audit.txt file\n");
    printf("\n");
    printf("Misc:\n");
    printf("    -d = debug this program\n");
    printf("    -v = Enable SleuthKit verbose flag\n");
    printf("\n");
    print_version();
    exit(1);
}



extern "C" int main(int argc, char * const *argv1) {
    int ch;
    fiwalk o;
    o.command_line = xml::make_command_line(argc,argv1);

    TSK_TCHAR * const *argv;

#ifdef TSK_WIN32
    char *opt_arg = NULL;
    char *argv_0 = NULL;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        fprintf(stderr,"Error getting wide arguments\n");
        exit(1);
    }
#else
    argv = (TSK_TCHAR * const*) argv1;
#endif

    while ((ch = GETOPT(argc, argv, _TSK_T("A:a:C:dfG:gmv1IMX:S:T:VZn:c:b:xOYzh?"))) > 0 ) { // s: removed
	switch (ch) {
	case _TSK_T('1'): o.opt_sha1 = true;break;
	case _TSK_T('m'):
	    o.opt_body_file = 1;
	    o.opt_sha1 = 0;
	    o.opt_md5  = 1;
	    o.t = stdout;
	    break;
	case _TSK_T('A'):
#ifdef TSK_WIN32
            convert(OPTARG, &opt_arg);
            o.arff_fn = opt_arg;
#else
            o.arff_fn = OPTARG;
#endif
            break;
	case _TSK_T('C'): o.file_count_max = TATOI(OPTARG);break;
	case _TSK_T('d'): o.opt_debug++; break;
	case _TSK_T('f'): o.opt_magic = true;break;
	case _TSK_T('g'): o.opt_no_data = true; break;
        case _TSK_T('b'): o.opt_get_fragments = false; break;
	case _TSK_T('G'): o.opt_maxgig = TATOI(OPTARG);break;
	case _TSK_T('h'): usage(o); break;
	case _TSK_T('I'): o.opt_ignore_ntfs_system_files=true;break;
	case _TSK_T('M'): o.opt_md5 = true; break;
	case _TSK_T('O'): o.opt_allocated_only=true; break;
	case _TSK_T('S'):
            o.opt_sector_hash = true;
            o.sectorhash_size = TATOI(OPTARG); break;
	case _TSK_T('T'):
#ifdef TSK_WIN32
            convert(OPTARG, &opt_arg);
            o.text_fn = opt_arg;
#else
            o.text_fn = OPTARG;
#endif
            break;
	case _TSK_T('V'): print_version();exit(0);
	case _TSK_T('X'):
#ifdef TSK_WIN32
            convert(OPTARG, &opt_arg);
            o.xml_fn = string(opt_arg);
#else
            o.xml_fn = string(OPTARG);
#endif
            break;
	case _TSK_T('Y'): o.opt_variable = false;break;
	case _TSK_T('x'): o.opt_x = true;break;
	case _TSK_T('Z'): o.opt_zap = true;break;
	case _TSK_T('a'):
#ifdef TSK_WIN32
            convert(OPTARG, &opt_arg);
            o.audit_file = opt_arg;
#else
            o.audit_file = OPTARG;
#endif
            break;
	case _TSK_T('c'):
#ifdef TSK_WIN32
            convert(OPTARG, &opt_arg);
            o.config_file = opt_arg;
#else
            o.config_file = OPTARG;
#endif
            break;
	case _TSK_T('n'):

#ifdef TSK_WIN32
            convert(OPTARG, &opt_arg);
            o.namelist.push_back(opt_arg);
#else
            o.namelist.push_back(OPTARG);
#endif
            break;
	    //case 's': save_outdir = optarg; opt_save = true; break;
	case _TSK_T('v'): tsk_verbose++; break; 			// sleuthkit option
	case _TSK_T('z'): o.opt_sha1=false; o.opt_md5=false; break;
	case _TSK_T('?'): usage(o);break;
	default:
	    fprintf(stderr, "Invalid argument: %" PRIttocTSK "\n", argv[OPTIND]);
	    usage(o);
	}
    }

    if (OPTIND >= argc) usage(o);
    argc -= OPTIND;
    argv += OPTIND;
    argv1 += OPTIND;

#ifdef TSK_WIN32
    convert(argv[0],&argv_0);
    o.filename = argv_0;
#else
    o.filename = argv[0];
#endif
    if (o.filename==0){
	errx(1,"must provide filename");
    }
    o.opt_parent_tracking = true;

    o.argc = argc;
    o.argv = argv1;
    o.run();

    return(0);
}
