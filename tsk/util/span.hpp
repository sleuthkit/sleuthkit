#pragma once

#include <cstddef>
#include <iterator>
#include <stdexcept>
#include <type_traits>

// TODO(JTS): We really should just use gsl::span

// A non-owning view over a contiguous array of T.
// Stores a pointer and element count but does NOT manage memory — the caller
// is responsible for ensuring the underlying buffer outlives the span.
// This is a lightweight substitute for std::span (C++20) or gsl::span.
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
  pointer _storage{};   // Pointer to the first element
  index_type _count{};  // Number of elements in the view

 public:
  // Constructs an empty (invalid) span
  span() = default;
  span(std::nullptr_t) noexcept : span() {}

  // Constructs a span over n elements starting at p
  span(pointer p, index_type n) noexcept : _storage{p}, _count{n} {}

  // Constructs a span from a fixed-size C array; count is deduced at compile time
  template <size_t N>
  span(element_type (&arr)[N]) noexcept : span(arr, N) {}

  // Constructs a span from a [first, last) pointer range
  span(pointer first, pointer last) noexcept
      : span(first, std::distance(first, last)) {}

  // Returns the number of elements in the span
  index_type count() const noexcept { return _count; }

  // Returns true if the span points to a non-null buffer
  bool valid() const noexcept { return _storage != nullptr; }

  // Returns the raw pointer to the start of the span
  pointer data() const noexcept { return _storage; }
};

// A non-owning view over a raw byte buffer (span<char>).
// Adds the ability to reinterpret the bytes as a pointer to a specific type,
// with a bounds check to ensure the buffer is large enough to hold that type.
// Typically used to parse on-disk or on-wire structures from a byte array.
struct memory_view : public span<char> {
  using span::span;

  // Reinterprets the byte buffer as a pointer to T.
  // Throws std::runtime_error if the buffer is smaller than sizeof(T).
  template <typename T>
  T* as() const {
    if ((size_t) count() < sizeof(T)) {
      throw std::runtime_error("not enough space");
    }

    return reinterpret_cast<T*>(_storage);
  }
};
