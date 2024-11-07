#include <fstream>
#include <cstdio>
#include <cstring>

#include "tsk/base/tsk_base.h"
#include "tools/vstools/mmls.h"
#include "catch.hpp"
#include "test/runner.h"

struct mocker {
    int index {0};
    mocker(){};
    int mocked_getopt([[maybe_unused]] int argc,
                      [[maybe_unused]] TSK_TCHAR** argv,
                      [[maybe_unused]] const TSK_TCHAR *option_string) {
        switch (index++) {
        case 0:
            return 'h';
        default:
            return -1;
        }
    };
};

static mocker *mock = nullptr;

#undef GETOPT
#define GETOPT(x,y,z) mock->mocked_getopt(x,y,z)
#define mmls_main(x,y) mocked_mmls_main(x,y)

#include "tools/vstools/mmls.cpp" // Assuming your getopt() logic is in this file

static char **setup(const char *a,const char *b,const char *c)
{
    char **argv = (char **)calloc(4,sizeof(char *));
    argv[0] = a ? strdup(a) : NULL;
    argv[1] = b ? strdup(b) : NULL;
    argv[2] = c ? strdup(c) : NULL;
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
    int argc=2;
    char **argv = setup("mmls","-h",nullptr);

    /* Capture the output */
    {
        runner::tempfile tf("mmls_1");
        tsk_stderr = tf.file;
        mock = new mocker();
        CHECK(mocked_mmls_main(argc, argv)==1);
        fflush(tf.file);

        auto first_line = tf.first_tsk_utf8_line();
        CHECK( first_line.substr(0,6) == "usage:" );
        tsk_stderr = stderr;
    }

    setdown(argv);
}
