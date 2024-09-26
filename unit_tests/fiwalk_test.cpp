/*
 * fiwalk_test.cpp
 *
 *  2024-09-29 - slg - modified to read from TEST_IMAGES the paths for the disk images
 *  2024-09-12 - slg - created
 *
 */

#include <iostream>

#include "tools/fiwalk/src/fiwalk.h"
#include "catch.hpp"

TEST_CASE("test_disk_images","[fiwalk]") {
    const char *disk_images_path = ::getenv("TEST_IMAGES");
    if (disk_images_path==NULL) {
        FAIL("Set environment variable TEST_IMAGES");
    }
    std::ifstream test_images(disk_images_path);
    CHECK( test_images.is_open());
    std::string line;
    while (std::getline(test_images, line)) {
        auto tab = line.find('\t');
        if (tab<0) {
            FAIL("No tab in line: " << line);
        }
        std::string src_image  = line.substr(0,tab);
        CAPTURE(src_image);

        /* the output XML file should be the XML file with a 2 added.
         * If there is no XML file, then add ".xml2" to the image file.
         */

        std::string dfxml_file  = line.substr(tab+1);
        std::string dfxml2_file = src_image + ".xml2";
        INFO("dfxml_file: " << dfxml_file);
        if (dfxml_file.back()=='\n'){
            dfxml_file = dfxml_file.substr(0, dfxml_file.length()-1);
            dfxml2_file = dfxml_file + "2";
        }
        INFO("test: fiwalk " << src_image)

        const int argc = 1;
        char* const argv[] = {
          &src_image[0],
          nullptr
        };

        if (access(argv[0], F_OK)==0){
            fiwalk o;
            o.filename = argv[0];
            o.argc = argc;
            o.argv = argv;
            o.opt_variable = false;
            o.opt_zap = true;
            o.xml_fn = dfxml2_file;
            o.run();
            CHECK(o.file_count>0);
            SUCCEED(src_img << " file count = " << o.file_count);
        } else {
            FAIL(src_img << " not found");
        }
        /* XML files are checked by the python driver */
    }
}
