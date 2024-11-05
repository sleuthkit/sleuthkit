#include "tsk/img/aff4.h"

#include <aff4/libaff4-c.h>

#include "catch.hpp"

TEST_CASE("test_get_messages_zero") {
  CHECK(get_messages(nullptr) == "");
}

TEST_CASE("test_get_messages_one") {
  AFF4_Message msg{0, "whatever", nullptr};
  CHECK(get_messages(&msg) == "whatever\n");
}

TEST_CASE("test_get_messages_many") {
  AFF4_Message msg2{0, "two", nullptr};
  AFF4_Message msg1{0, "one", &msg2};
  AFF4_Message msg0{0, "zero", &msg1};
  CHECK(get_messages(&msg0) == "zero\none\ntwo\n");
}
