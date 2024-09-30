/*
 * fiwalk_test.cpp
 *
 *  2024-09-29 - slg - modified to read from TEST_IMAGES the paths for the disk images
 *  2024-09-12 - slg - created
 *
 */

#include <fstream>
#include <string>

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "tools/fiwalk/src/fiwalk.h"

TEST_CASE("test_disk_images","[fiwalk]") {
    std::ifstream test_images("tests/test_images.txt");
    CHECK(test_images.is_open());
    std::string line;
    while (std::getline(test_images, line)) {
        auto tab = line.find('\t');
        if (tab == std::string::npos) {
            FAIL("No tab in line: " << line);
        }
        std::string src_image  = line.substr(0, tab);
        CAPTURE(src_image);

        /* the output XML file should be the XML file with a 2 added.
         * If there is no XML file, then add ".xml2" to the image file.
         */

        const std::string dfxml_file = tab + 1 > line.length() ? "" : line.substr(tab + 1);
        std::string dfxml2_file = dfxml_file.empty() ? src_image + ".xml2" : dfxml_file + "2";

        INFO("test: fiwalk " << src_image)

        const int argc = 1;
        char* const argv[] = {
          &src_image[0],
          nullptr
        };

        if (access(argv[0], F_OK) == 0){
            fiwalk o;
            o.filename = argv[0];
            o.argc = argc;
            o.argv = argv;
            o.opt_variable = false;
            o.opt_zap = true;
            o.xml_fn = dfxml2_file;
            o.run();
            CHECK(o.file_count > 0);
            SUCCEED(src_image << " file count = " << o.file_count);
        }
        else {
            FAIL(src_image << " not found");
        }
        /* XML files are checked by the python driver */
    }
}
