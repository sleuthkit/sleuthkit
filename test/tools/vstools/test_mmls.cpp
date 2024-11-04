#include <fstream>
#include <cstdio>
#include <cstring>

#include "tsk/base/tsk_base.h"
#include "tools/vstools/mmls.h"
#include "catch.hpp"
#include "test/runner.h"

#include "tools/vstools/mmls.cpp" // Assuming your getopt() logic is in this file

TEST_CASE("Test for running mmls", "[getopt]") {
    auto mock_getopt = []([[maybe_unused]] int argc, [[maybe_unused]] char** argv) -> int {
        // Implement your mock logic here
        // For example, return specific values based on the current iteration
        static int index = 0;
        switch (index++) {
            case 0:
                return 'h';
            default:
                return -1;
        }
    };

    int result = mmls_main(0, nullptr);
}
