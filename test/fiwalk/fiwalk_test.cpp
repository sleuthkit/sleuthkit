/*
 * fiwalk_test.cpp
 *
 *  2024-09-29 - slg - modified to read from TEST_IMAGES the paths for the disk images
 *  2024-09-12 - slg - created
 *  2025-03-30 - slg - modified to base paths from getenv("DEFAULT_SLEUTHKIT_TEST_DATA_DIR") or "../sleuthkit_test_data" if it is not defined.
 *
 */

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include <cstdlib>
#include <string>

#include "tools/fiwalk/src/fiwalk.h"

#define SLEUTHKIT_TEST_DATA_DIR "SLEUTHKIT_TEST_DATA_DIR"
#define DEFAULT_SLEUTHKIT_TEST_DATA_DIR "../sleuthkit_test_data"

void check_image(std::string img_path, std::string dfxml2_path) {
    const char *data_dir = std::getenv(SLEUTHKIT_TEST_DATA_DIR);
    if (data_dir == nullptr){
        data_dir = DEFAULT_SLEUTHKIT_TEST_DATA_DIR;
    }

    /* the output XML file should be the XML file with a 2 added.
     * If there is no XML file, then add ".xml2" to the image file.
     */
    if (dfxml2_path.empty()) {
        dfxml2_path = std::string(data_dir) + std::string("/") +  img_path + std::string(".xml2");
    }
    else {
        dfxml2_path   = std::string(data_dir) + std::string("/") + dfxml2_path + std::string("2");
    }

    img_path = std::string(data_dir) + std::string("/") + img_path;

    CAPTURE(img_path);
    INFO("test: fiwalk " << img_path)

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
      "from_brian/imageformat_mmls_1.E01",
      "from_brian/imageformat_mmls_1.E01.xml"
    );
}

TEST_CASE("test_disk_images btrfs_test_image.E01 btrfs", "[fiwalk]") {
    check_image(
      "btrfs/btrfs_testimage_50MB.E01",
      ""
    );
}

TEST_CASE("test_disk_images 2GB-xfs-raw.E01", "[fiwalk]") {
    check_image(
      "xfs/xfs-raw-2GB.E01",
      ""
    );
}
#endif

TEST_CASE("test_disk_images ntfs-img-kw-1.dd", "[fiwalk]") {
    check_image(
      "from_brian/3-kwsrch-ntfs/ntfs-img-kw-1.dd",
      "from_brian/3-kwsrch-ntfs/3-kwsrch-ntfs.xml"
    );
}

TEST_CASE("test_disk_images ext3-img-kw-1.dd", "[fiwalk]") {
    check_image(
      "from_brian/4-kwsrch-ext3/ext3-img-kw-1.dd",
      "from_brian/4-kwsrch-ext3/ext3-img-kw-1.dd.xml"
    );
}

TEST_CASE("test_disk_images daylight.dd", "[fiwalk]") {
    check_image(
      "from_brian/5-fat-daylight/daylight.dd",
      "from_brian/5-fat-daylight/daylight.xml"
    );
}

TEST_CASE("test_disk_images image.gen1.dmg", "[fiwalk]") {
    check_image(
      "nps-2009-hfsjtest1/image.gen1.dmg",
      "nps-2009-hfsjtest1/image.gen1.xml"
    );
}

TEST_CASE("test_disk_images image.dd", "[fiwalk]") {
    check_image(
      "ufs/image.E01",
      "ufs/image_dd.xml"
    );
}

TEST_CASE("test_disk_images iso-dirtree1.iso", "[fiwalk]") {
    check_image(
      "from_brian/14-iso9660-1/iso-dirtree1.iso",
      ""
    );
}

TEST_CASE("test_disk_images fat-img-kw.dd", "[fiwalk]") {
    check_image(
      "from_brian/2-kwsrch-fat/fat-img-kw.dd",
      ""
    );
}

TEST_CASE("test_disk_images 6-fat-undel.dd", "[fiwalk]") {
    check_image(
      "from_brian/6-fat-undel.dd",
      ""
    );
}

TEST_CASE("test_disk_images image.gen1.dmg hfsj1", "[fiwalk]") {
    check_image(
      "nps-2009-hfsjtest1/image.gen1.dmg",
      ""
    );
}
