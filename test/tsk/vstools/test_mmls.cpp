#include "tsk/base/tsk_base.h"
#include "tools/vstools/mmls.h"
#include "catch.hpp"
#include <fstream>
#include <cstdio>

static const char *EXFAT1_OUTPUT=
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
    "005:  -------   0000194560   0000195352   0000000793   Unallocated\n";

static const char *EXFAT1_CSV_OUTPUT=
    "ID,Slot,Start,End,Length,Description\n"
    "000,Meta,0000000000,0000000000,0000000001,Safety Table\n"
    "001,,0000000000,0000002047,0000002048,Unallocated\n"
    "002,Meta,0000000001,0000000001,0000000001,GPT Header\n"
    "003,Meta,0000000002,0000000033,0000000032,Partition Table\n"
    "004,000,0000002048,0000194559,0000192512,disk image\n"
    "005,,0000194560,0000195352,0000000793,Unallocated\n";


static char **setup(const char *a,const char *b,const char *c)
{
    char**argv;
    argv = (char **)calloc(4,sizeof(char *));
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

TEST_CASE("mmls -h", "[vstools]") {
    auto hold = OPTIND;
    char **argv = setup("mmls","-h","");

    /* Capture the output */
    char filename[64];
    strcpy(filename,"/tmp/mmls_outXXXXXX");
    mkstemp(filename);
    FILE *f = fopen(filename,"w+");
    tsk_stderr = f;
    CHECK(mmls_main(2, argv)==1);
    fflush(f);
    tsk_stderr = stderr;
    fseeko(f,0L,0);
    /* Now verify at least the first line */
    char buf[65536];
    memset(buf,0,sizeof(buf));
    char *l = fgets(buf, sizeof(buf), f);
    fclose(f);
    CHECK(strncmp(buf,"usage:",6)==0);
    unlink(filename);
    setdown(argv);
    OPTIND = hold;
}

TEST_CASE("mmls test/from_brian/exfat1.E01", "[vstools]") {
    auto hold = OPTIND;
    char **argv = setup("mmls","test/from_brian/exfat1.E01","");

    /* Capture the output */
    char filename[64];
    strcpy(filename,"/tmp/mmls_outXXXXXX");
    mkstemp(filename);
    FILE *f = fopen(filename,"w+");
    tsk_stdout = f;
    CHECK(mmls_main(2, argv)==0);
    fflush(f);
    tsk_stdout = stdout;
    fseeko(f,0L,0);
    /* Now verify the data */
    char buf[65536];
    memset(buf,0,sizeof(buf));
    read(fileno(f),buf,sizeof(buf));
    fclose(f);
    CHECK(strcmp(buf,EXFAT1_OUTPUT)==0);
    unlink(filename);
    setdown(argv);
    OPTIND = hold;
}

TEST_CASE("mmls -c test/from_brian/exfat1.E01", "[vstools]") {
    auto hold = OPTIND;
    char **argv = setup("mmls","-c","test/from_brian/exfat1.E01");

    /* Capture the output */
    char filename[64];
    strcpy(filename,"/tmp/mmls_outXXXXXX");
    mkstemp(filename);
    FILE *f = fopen(filename,"w+");
    tsk_stdout = f;
    CHECK(mmls_main(3, argv)==0);
    fflush(f);
    tsk_stdout = stdout;
    fseeko(f,0L,0);
    /* Now verify the data */
    char buf[65536];
    memset(buf,0,sizeof(buf));
    read(fileno(f),buf,sizeof(buf));
    fclose(f);
    CHECK(strcmp(buf,EXFAT1_CSV_OUTPUT)==0);
    unlink(filename);
    setdown(argv);
    OPTIND = hold;
}
