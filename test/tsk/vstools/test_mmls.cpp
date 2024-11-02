#include "tsk/base/tsk_base.h"
#include "tools/vstools/mmls.h"
#include "catch.hpp"
#include <fstream>
#include <cstdio>

const char *EXFAT1_OUTPUT=
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

const char *EXFAT1_CSV_OUTPUT=
    "ID,Slot,Start,End,Length,Description\n"
    "000,Meta,0000000000,0000000000,0000000001,Safety Table\n"
    "001,,0000000000,0000002047,0000002048,Unallocated\n"
    "002,Meta,0000000001,0000000001,0000000001,GPT Header\n"
    "003,Meta,0000000002,0000000033,0000000032,Partition Table\n"
    "004,000,0000002048,0000194559,0000192512,disk image\n"
    "005,,0000194560,0000195352,0000000793,Unallocated\n";


TEST_CASE("mmls", "[vstools]") {
    int argc = 2;
    char**argv;
    argv = (char **)calloc(3,sizeof(3));
    argv[0] = strdup("mmls");
    argv[1] = strdup("-h");

    /* Capture the output */
    char filename[64];
    strcpy(filename,"/tmp/mmls_outXXXXXX");
    mkstemp(filename);
    printf("filename:%s\n",filename);
    FILE *f = fopen(filename,"w+");
    tsk_stderr = f;
    CHECK(mmls_main(argc, argv)!=0);
    fflush(f);
    tsk_stderr = stderr;
    fseeko(f,0L,0);
    /* Now verify at least the first line */
    char line[1024];
    line[0] == 0;
    char *l = fgets(line, sizeof(line), f);
    printf("line:%s\n",line);
    CHECK(strncmp(line,"usage:",6)==0);
    fclose(f);
    //unlink(filename);
    free(argv[1]);
    free(argv[0]);
    free(argv);
}
