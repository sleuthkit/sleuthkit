#include "tsk/img/aff4.h"

#include <aff4/libaff4-c.h>

#include "catch.hpp"

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
