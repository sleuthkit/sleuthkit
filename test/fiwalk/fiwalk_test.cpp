/*
 * fiwalk_test.cpp
 *
 *  2024-09-29 - slg - modified to read from TEST_IMAGES the paths for the disk images
 *  2024-09-12 - slg - created
 *
 */

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include <string>

#include "tools/fiwalk/src/fiwalk.h"

void check_image(std::string img_path, std::string dfxml2_path) {
    CAPTURE(img_path);
    INFO("test: fiwalk " << img_path)

    /* the output XML file should be the XML file with a 2 added.
     * If there is no XML file, then add ".xml2" to the image file.
     */
    if (dfxml2_path.empty()) {
      dfxml2_path = img_path + ".xml2";
    }
    else {
      dfxml2_path += "2";
    }

    const int argc = 1;
    char* const argv[] = { &img_path[0], nullptr };

    if (access(argv[0], F_OK) == 0){
        fiwalk o;
        o.filename = argv[0];
        o.argc = argc;
        o.argv = argv;
        o.opt_variable = false;
        o.opt_zap = true;
        o.opt_md5 = true;               // compute the MD5 of every file (for testing file extraction)
        o.opt_sha1 = true;              // compute SHA1
        o.xml_fn = dfxml2_path;
        o.run();
        CHECK(o.file_count > 0);
        SUCCEED(img_path << " file count = " << o.file_count);
    }
    else {
        FAIL(img_path << " not found");
    }
    /* XML files are checked by the python driver */
}

#ifdef HAVE_LIBEWF
TEST_CASE("test_disk_images imageformat_mmls_1.E01", "[fiwalk]") {
    check_image(
      "test/from_brian/imageformat_mmls_1.E01",
      "test/from_brian/imageformat_mmls_1.E01.xml"
    );
}

TEST_CASE("test_disk_images btrfs_test_image.E01 btrfs", "[fiwalk]") {
    check_image(
      "test/from_brian/btrfs_testimage_50MB.E01",
      ""
    );
}

TEST_CASE("test_disk_images 2GB-xfs-raw.E01", "[fiwalk]") {
    check_image(
      "test/from_brian/2GB-xfs-raw.E01",
      ""
    );
}
#endif

TEST_CASE("test_disk_images ntfs-img-kw-1.dd", "[fiwalk]") {
    check_image(
      "test/from_brian/ntfs-img-kw-1.dd",
      "test/from_brian/3-kwsrch-ntfs.xml"
    );
}

TEST_CASE("test_disk_images ext3-img-kw-1.dd", "[fiwalk]") {
    check_image(
      "test/from_brian/ext3-img-kw-1.dd",
      ""
    );
}

TEST_CASE("test_disk_images daylight.dd", "[fiwalk]") {
    check_image(
      "test/from_brian/daylight.dd",
      ""
    );
}

TEST_CASE("test_disk_images image.gen1.dmg", "[fiwalk]") {
    check_image(
      "test/from_brian/image.gen1.dmg",
      ""
    );
}

TEST_CASE("test_disk_images image.dd", "[fiwalk]") {
    check_image(
      "test/from_brian/image.dd",
      "test/from_brian/image_dd.xml"
    );
}

TEST_CASE("test_disk_images iso-dirtree1.iso", "[fiwalk]") {
    check_image(
      "test/from_brian/iso-dirtree1.iso",
      ""
    );
}

TEST_CASE("test_disk_images fat-img-kw.dd", "[fiwalk]") {
    check_image(
      "test/from_brian/fat-img-kw.dd",
      ""
    );
}

TEST_CASE("test_disk_images 6-fat-undel.dd", "[fiwalk]") {
    check_image(
      "test/from_brian/6-fat-undel.dd",
      ""
    );
}

TEST_CASE("test_disk_images image.gen1.dmg hfsj1", "[fiwalk]") {
    check_image(
      "test/from_brian/image.gen1.dmg",
      ""
    );
}

