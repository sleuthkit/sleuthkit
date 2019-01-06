#pragma once

#include <cstddef>
#include <iterator>
#include <stdexcept>
#include <type_traits>

// TODO(JTS): We really should just use gsl::span

template <typename T>
class span {
  // TODO(JTS): Finish this to make it useful
 public:
  using element_type = T;
  using index_type = size_t;
  using pointer = T*;
  using reference = T&;
  using value = std::remove_cv_t<T>;

 protected:
  pointer _storage{};
  index_type _count{};

 public:
  span() = default;
  span(std::nullptr_t) noexcept : span() {}

  span(pointer p, index_type n) noexcept : _storage{p}, _count{n} {}

  template <size_t N>
  span(element_type (&arr)[N]) noexcept : span(arr, N) {}

  span(pointer first, pointer last) noexcept
      : span(first, std::distance(first, last)) {}

  index_type count() const noexcept { return _count; }

  bool valid() const noexcept { return _storage != nullptr; }
  pointer data() const noexcept { return _storage; }
};

struct memory_view : public span<char> {
  using span::span;

  template <typename T>
  T* as() const {
    // if ((size_t) count() < sizeof(T)) {
    //  throw std::runtime_error("not enough space");
    //}

    return reinterpret_cast<T*>(_storage);
  }
};
