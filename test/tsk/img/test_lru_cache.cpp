#include "tsk/img/lru_cache.h"

#include <iterator>
#include <utility>

#include "catch.hpp"

template <class Cache>
void insert(Cache& c, int l, int r) {
  // insert new items
  for (int i = l; i < r; ++i) {
    c.put(i, i);
  }
}

template <class Cache>
void get(Cache& c, int l, int r) {
  // check that the items are present, destructively
  for (int i = l; i < r; ++i) {
    const int* v = c.get(i);
    REQUIRE(v);
    REQUIRE(i == *v);
  }
}

template <class Cache>
void peek(Cache& c, int l, int r) {
  int i = r - 1;
  for (const auto& act: c) {
    // check that the last n inserted items are there, nondestructively
    const std::pair<int, int> exp{i, i};
    REQUIRE(exp == act);
    --i;
    if (i < l) {
      break;
    }
  }
}

TEST_CASE("insert_10_LRU_10") {
  LRUCache<int, int> c(10);
  insert(c, 0, 10);
  peek(c, 0, 10);
  get(c, 0, 10);
}

TEST_CASE("insert_20_LRU_10") {
  LRUCache<int, int> c(10);
  insert(c, 0, 20);
  peek(c, 10, 20);
  get(c, 10, 20);
}

TEST_CASE("lru_size") {
  LRUCache<int, int> c(10);
  CHECK(c.size() == 10);
}

TEST_CASE("lru_clear") {
  LRUCache<int, int> c(10);
  insert(c, 0, 10);
  REQUIRE(std::distance(c.begin(), c.end()) == 10);
  c.clear();
  REQUIRE(std::distance(c.begin(), c.end()) == 0);
}
