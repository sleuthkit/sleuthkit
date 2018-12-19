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
  constexpr span() noexcept = default;
  constexpr span(std::nullptr_t) noexcept : span() {}

  constexpr span(pointer p, index_type n) noexcept : _storage{p}, _count{n} {}

  template <size_t N>
  constexpr span(element_type (&arr)[N]) noexcept : span(arr, N) {}

  constexpr span(pointer first, pointer last) noexcept
      : span(first, std::distance(first, last)) {}

  constexpr span(const span&) noexcept = default;
  constexpr span& operator=(const span&) noexcept = default;

  constexpr span(span&&) noexcept = default;
  constexpr span& operator=(span&&) noexcept = default;

  constexpr index_type count() const noexcept { return _count; }

  constexpr bool valid() const noexcept { return _storage != nullptr; }
  constexpr pointer data() const noexcept { return _storage; }
};

struct memory_view : public span<char> {
  using span::span;

  template <typename T>
  constexpr T* as() const {
    // if ((size_t) count() < sizeof(T)) {
    //  throw std::runtime_error("not enough space");
    //}

    return reinterpret_cast<T*>(_storage);
  }
};
