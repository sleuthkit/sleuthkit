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
    int argc_ = 1;
    char *  *argv_ = (char *  *)calloc(sizeof(char *), argc_+1);
    argv_[0] = strdup("../tests/data/img/image.dd");
    argv_[1] = 0;
    if (access(argv_[0], F_OK)==0){
        fiwalk o;
        o.filename = argv_[0];
        o.argc = argc_;
        o.argv = argv_;
        o.opt_variable = false;
        o.opt_zap = true;
        o.opt_parent_tracking = true;
        o.xml_fn = "/tmp/tests_data_img_image_dd.xml";
        o.run();
        CHECK(o.file_count>0);
        fprintf(stderr,"%s file count = %d\n",argv_[0],o.file_count);
    } else {
        fprintf(stderr,"%s not found",argv_[0]);
    }
    free(argv_);
}

TEST_CASE("image.gen1.dmg.xml","[fiwalk]") {
    int argc_ = 1;
    /* Next image */
    char *  *argv_ = (char *  *)calloc(sizeof(char *), argc_+1);
    std::string  from_brian = getenv("HOME") + std::string("/from_brian");
    std::string  fname = from_brian + "/image.gen1.dmg";
    argv_[0] = strdup(fname.c_str());
    argv_[1] = 0;
    if (access(argv_[0], F_OK)==0){
        fiwalk o;
        o.filename = argv_[0];
        o.argc = argc_;
        o.argv = argv_;
        o.xml_fn = "/tmp/from_brian_image_gen1_dmg.xml";
        o.opt_variable = false;
        o.opt_zap = true;
        o.opt_parent_tracking = true;
        o.run();
        CHECK(o.file_count>0);
        fprintf(stderr,"%s file count = %d\n",argv_[0],o.file_count);
    } else {
        fprintf(stderr,"%s not found",argv_[0]);
    }
    free(argv_);
}
