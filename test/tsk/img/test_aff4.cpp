#include "tsk/img/aff4.h"

#include <aff4/libaff4-c.h>

#include <cstring>

#include "catch.hpp"

TEST_CASE("test_get_messages_zero") {
  CHECK(!get_messages(nullptr));
}

TEST_CASE("test_get_messages_one") {
  AFF4_Message msg{0, "whatever", nullptr};
  std::unique_ptr<char[], decltype(&free)> m{get_messages(&msg), free};
  CHECK(std::strcmp(m.get(), "whatever\n"));
}

TEST_CASE("test_get_messages_many") {
  AFF4_Message msg2{0, "two", nullptr};
  AFF4_Message msg1{0, "one", &msg2};
  AFF4_Message msg0{0, "zero", &msg1};
  std::unique_ptr<char[], decltype(&free)> m{get_messages(&msg0), free};
  CHECK(std::strcmp(m.get(), "zero\none\ntwo\n"));
}
