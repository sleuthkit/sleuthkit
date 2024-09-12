/*
 * fiwalk_test.cpp
 *
 *  Sept. 12, 2024 - Simsong - created
 */

#include <tsk_config.h>
#include <libtsk.h>
#include "tools/fiwalk/src/fiwalk.h"
#include "catch.hpp"


TEST_CASE("fiwalk","[fiwalk]") {
    int argc_ = 4;
    const char **argv_ = (const char **)calloc(sizeof(char *), argc_+1);
    argv_[0] = "fiwalk";
    argv_[1] = "-YZ";                   // no <creator>, and zap the output
    argv_[2] = "-X/tmp/fiwalk_image.xml";
    argv_[3] = "../tests/data/img/image.dd";
    fiwalk_main(argc_,argv_);
}
