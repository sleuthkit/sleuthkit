#include <fstream>
#include <cstdio>
#include <cstring>

#include "tsk/base/tsk_base.h"
#include "tools/vstools/mmls.h"
#include "catch.hpp"
#include "test/runner.h"



static const std::string EXFAT1_OUTPUT(
    "GUID Partition Table (EFI)\n"
    "Offset Sector: 0\n"
    "Units are in 512-byte sectors\n"
    "\n"
    "      Slot      Start        End          Length       Description\n"
    "000:  Meta      0000000000   0000000000   0000000001   Safety Table\n"
    "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
    "002:  Meta      0000000001   0000000001   0000000001   GPT Header\n"
    "003:  Meta      0000000002   0000000033   0000000032   Partition Table\n"
    "004:  000       0000002048   0000194559   0000192512   disk image\n"
    "005:  -------   0000194560   0000195352   0000000793   Unallocated\n");

static const std::string EXFAT1_CSV_OUTPUT(
    "ID,Slot,Start,End,Length,Description\n"
    "000,Meta,0000000000,0000000000,0000000001,Safety Table\n"
    "001,,0000000000,0000002047,0000002048,Unallocated\n"
    "002,Meta,0000000001,0000000001,0000000001,GPT Header\n"
    "003,Meta,0000000002,0000000033,0000000032,Partition Table\n"
    "004,000,0000002048,0000194559,0000192512,disk image\n"
    "005,,0000194560,0000195352,0000000793,Unallocated\n");


static char **setup(const char *a,const char *b,const char *c)
{
    char **argv = (char **)calloc(4,sizeof(char *));
    argv[0] = strdup(a);
    argv[1] = strdup(b);
    argv[2] = strdup(c);
    argv[3] = NULL;
    return argv;
}

static void setdown(char **argv)
{
    for(int i=0;i<4;i++){
        if(argv[i]) free(argv[i]);
    }
    free(argv);
}

static void show(int argc,char **argv)
{
    printf("============= show argc=%d argv=%p\n",argc,argv);
    for(int i=0;i<argc;i++){
        printf("argv[%d]=%s\n",i,argv[i]);
    }
}


TEST_CASE("mmls -h", "[vstools]") {
    int argc=2;
    char **argv = setup("mmls","-h","");

    /* Capture the output */
    runner::tempfile tf("mmls_1");

    tsk_stderr = tf.file;
    show(argc,argv);
    {
        optind = 1;//        runner::save_getopt save;
        CHECK(mmls_main(argc, argv)==1);
    }
    tsk_stderr = stderr;

    auto first_line = tf.first_line();
    CHECK( first_line.substr(0,6) == "usage:" );
    setdown(argv);
}

TEST_CASE("mmls test/from_brian/exfat1.E01", "[vstools]") {
    int argc = 2;
    char **argv = setup("mmls","test/from_brian/exfat1.E01","");

    /* Capture the output */
    runner::tempfile tf("mmls_2");
    tsk_stdout = tf.file;
    show(argc,argv);
    {
        optind = 1; //runner::save_getopt save;
        CHECK(mmls_main(argc, argv)==0);
    }
    tsk_stdout = stdout;

    CHECK( tf.validate_contains(EXFAT1_OUTPUT));
}

TEST_CASE("mmls -c test/from_brian/exfat1.E01", "[vstools]") {
    int argc=3;
    char **argv = setup("mmls","-c","test/from_brian/exfat1.E01");

    /* Capture the output */
    runner::tempfile tf("mmls_3");
    tsk_stdout = tf.file;
    show(argc,argv);
    {
        optind = 1; //       runner::save_getopt save;
        CHECK(mmls_main(argc, argv)==0);
    }
    tsk_stdout = stdout;

    CHECK( tf.validate_contains(EXFAT1_CSV_OUTPUT));
}
