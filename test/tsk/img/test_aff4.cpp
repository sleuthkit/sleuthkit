#include "tsk/img/aff4.h"

#if HAVE_LIBAFF4

#include <aff4/libaff4-c.h>
#include <memory>
#include <string>

#include "catch.hpp"
#include "test/tsk/img/test_img.h"  // <-- your shared test utilities

TEST_CASE("test_get_messages_zero") {
  CHECK(get_messages(nullptr) == "");
}

TEST_CASE("test_get_messages_one") {
  char s0[] = "whatever";
  AFF4_Message msg0{0, s0, nullptr};
  CHECK(get_messages(&msg0) == "whatever\n");
}

TEST_CASE("test_get_messages_many") {
  char s0[] = "zero";
  char s1[] = "one";
  char s2[] = "two";

  AFF4_Message msg2{0, s2, nullptr};
  AFF4_Message msg1{0, s1, &msg2};
  AFF4_Message msg0{0, s0, &msg1};
  CHECK(get_messages(&msg0) == "zero\none\ntwo\n");
}

TEST_CASE("aff4_open not a file") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("not_a_file"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    aff4_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("aff4_open not an aff4") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.dd"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    aff4_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

#endif
