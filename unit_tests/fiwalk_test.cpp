/*
 * fiwalk_test.cpp
 *
 *  Sept. 12, 2024 - Simsong - created
 */

#include <tsk_config.h>
#include <libtsk.h>
#include "tools/fiwalk/src/fiwalk.h"
#include "catch.hpp"


TEST_CASE("image.dd","[fiwalk]") {
    int argc_ = 4;
    const char **argv_ = (const char **)calloc(sizeof(char *), argc_+1);
    argv_[0] = "fiwalk";
    argv_[1] = "-YZ";                   // no <creator>, and zap the output
    argv_[2] = "-X/tmp/fiwalk_image.xml";
    argv_[3] = "../tests/data/img/image.dd";
    if (access(argv_[3], F_OK)==0){
        fiwalk_main(argc_,argv_);
    } else {
        fprintf(stderr,"%s not found",argv_[3]);
    }
    free(argv_);
}

TEST_CASE("image.gen1.dmg.xml","[fiwalk]") {
    int argc_ = 4;
    /* Next image */
    const char **argv_ = (const char **)calloc(sizeof(char *), argc_+1);
    std::string  from_brian = getenv("HOME") + std::string("/from_brian");
    std::string  fname = from_brian + "/image.gen1.dmg";
    argv_[0] = "fiwalk";
    argv_[1] = "-YZ";                   // no <creator>, and zap the output
    argv_[2] = "-X/tmp/image.gen1.dmg.xml";
    argv_[3] = fname.c_str();
    if (access(argv_[3], F_OK)==0){
        fiwalk_main(argc_,argv_);
    } else {
        fprintf(stderr,"%s not found",argv_[3]);
    }
    free(argv_);
}
