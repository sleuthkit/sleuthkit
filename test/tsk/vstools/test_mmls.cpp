#include "tsk/img/mult_files.h"

#include "catch.hpp"

TEST_CASE("mmls", "[vstools]") {
    char **argv = ["mmls","-h"];

    /* make sure help works */
    CHECK(mmls_main(argc, argv1)!=0);
}
