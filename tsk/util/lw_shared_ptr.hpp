#pragma once

#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>

struct in_place_t {};
static in_place_t in_place{};

/// A lightweight, non-thread-safe implementation of a shared_ptr.
///
/// This implementation has most of the functionality of std:shared_ptr, is
/// less costly to create, copy, and destroy, but creating, copying, or
/// destroying these smart pointers is not thread safe.
template <typename T>
class lw_shared_ptr {
 public:
  /// Constructs a shared_ptr with no managed object, i.e. empty shared_ptr
  lw_shared_ptr() = default;

  /// Constructs a shared_ptr with no managed object, i.e. empty shared_ptr
  lw_shared_ptr(std::nullptr_t) noexcept : lw_shared_ptr() {}

  /// Constructs a shared_ptr which shares ownership of the object managed by
  /// rhs.
  ///
  /// If rhs manages no object, `*this` manages no object too.
  lw_shared_ptr(const lw_shared_ptr& rhs) noexcept
      : _val{rhs._val}, _count{rhs._count} {
    if (_count != nullptr) {
      (*_count)++;
    }
  }

  /// Constructs a shared_ptr which shares ownership of the object managed by
  /// rhs.
  ///
  /// If rhs manages no object, `*this` manages no object too.
  template <typename U>
  lw_shared_ptr(const lw_shared_ptr<U>& rhs, T* val) noexcept
      : _val{val}, _count{rhs._count} {
    if (_count != nullptr) {
      (*_count)++;
    }
  }

  /// Move-constructs a shared_ptr from rhs.
  ///
  /// After the construction, `*this` contains a copy of the previous state of
  /// rhs, rhs is empty, and its stored pointer is null.
  lw_shared_ptr(lw_shared_ptr&& rhs) noexcept
      : _val{rhs._val}, _count{rhs._count} {
    if (this == &rhs) {
      return;
    }

    rhs._val = nullptr;
    rhs._count = nullptr;
  };

  /// Move-constructs a shared_ptr from rhs.
  ///
  /// After the construction, `*this` contains a copy of the previous state of
  /// rhs, rhs is empty, and its stored pointer is null.
  template <typename U,
            typename = std::enable_if_t<std::is_convertible<U*, T*>::value>>
  lw_shared_ptr(lw_shared_ptr<U>&& rhs) noexcept
      : _val{rhs._val}, _count{rhs._count} {
    if ((lw_shared_ptr<U>*)this == &rhs) {
      return;
    }
    rhs._val = nullptr;
    rhs._count = nullptr;
  };

  /// Inplace constructs an object of type T and wraps it in a lw_shared_ptr
  /// using args as the parameter list for the constructor of T.
  template <typename... Args>
  lw_shared_ptr(in_place_t, Args&&... args) {
    // For performance reasons we, store the object and reference count in
    // the same allocation.  To make sure accessing the reference count is
    // fast, we also make sure that the address of the count is properly
    // aligned.

    // Calculate the padded offset of the reference count
    const auto count_offset = sizeof(T) + (sizeof(T) % alignof(unsigned));

    // Allocate memory for the object as well as the reference count.
    auto mem = new uint8_t[count_offset + sizeof(unsigned)];

    // Construct the value and count values in our memory.
    _val = new (mem) T(std::forward<Args>(args)...);
    _count = new (mem + count_offset) unsigned();
  }

  /// Constructs a shared_ptr where T is move initialized by the value of rhs
  lw_shared_ptr(T&& rhs) {
    // For performance reasons we, store the object and reference count in
    // the same allocation.  To make sure accessing the reference count is
    // fast, we also make sure that the address of the count is properly
    // aligned.

    // Calculate the padded offset of the reference count
    const auto count_offset = sizeof(T) + (sizeof(T) % alignof(unsigned));

    // Allocate memory for the object as well as the reference count.
    auto mem = new uint8_t[count_offset + sizeof(unsigned)];

    // Construct the value and count values in our memory.
    _val = new (mem) T(std::forward<T>(rhs));
    _count = new (mem + count_offset) unsigned();
  }

  /// Destructs the owned object if no more shared_ptrs link to it.
  ///
  /// If `*this` owns an object and it is the last shared_ptr owning it, the
  /// object is destroyed through the owned deleter.
  ///
  /// After the destruction, the smart pointers that shared ownership with
  /// `*this`, if any, will report a use_count() that is one less than its
  /// previous value.
  [[gnu::always_inline]] inline ~lw_shared_ptr() noexcept(
      std::is_nothrow_destructible<T>::value) {
    if (_val != nullptr && (*_count)-- == 0) {
      // Destruct val
      _val->~T();

      // Free memory
      delete[](uint8_t*) _val;
    }

    _val = nullptr;
    _count = nullptr;
  }

  /// Replaces the managed object with the one managed by rhs, and shares the
  /// ownership of the object managed by rhs.
  ///
  /// If `*this` already owns an object and it is the last shared_ptr owning
  /// it, and rhs is not the same as `*this`, the object is destroyed through
  /// the owned deleter.
  lw_shared_ptr& operator=(const lw_shared_ptr& rhs) noexcept {
    if ((*this) != rhs) {
      this->~lw_shared_ptr();
      new (this) lw_shared_ptr(rhs);
    }

    return (*this);
  };

  /// Replaces the managed object with the one managed by rhs, and shares the
  /// ownership of the object managed by rhs.
  ///
  /// If `*this` already owns an object and it is the last shared_ptr owning
  /// it, and rhs is not the same as `*this`, the object is destroyed through
  /// the owned deleter.
  template <typename U,
            typename = std::enable_if_t<std::is_convertible<U*, T*>::value>>
  lw_shared_ptr& operator=(const lw_shared_ptr<U>& rhs) noexcept {
    if ((*this) != rhs) {
      this->~lw_shared_ptr();
      new (this) lw_shared_ptr(rhs);
    }

    return (*this);
  };

  /// Replaces the managed object with the one managed by rhs, and takes
  /// takes ownership of the object managed by rhs.
  ///
  /// After the assignment, `*this` contains a copy of the previous state of
  /// rhs and rhs is empty
  ///
  /// If `*this` already owns an object and it is the last shared_ptr owning
  /// it, and rhs is not the same as `*this`, the object is destroyed through
  /// the owned deleter.
  lw_shared_ptr& operator=(lw_shared_ptr&& rhs) noexcept {
    if ((*this) != rhs) {
      this->~lw_shared_ptr();
      new (this) lw_shared_ptr(std::forward<lw_shared_ptr>(rhs));
    }

    return (*this);
  };

  /// Replaces the managed object with the one managed by rhs, and takes
  /// takes ownership of the object managed by rhs.
  ///
  /// After the assignment, `*this` contains a copy of the previous state of
  /// rhs and rhs is empty
  ///
  /// If `*this` already owns an object and it is the last shared_ptr owning
  /// it, and rhs is not the same as `*this`, the object is destroyed through
  /// the owned deleter.
  template <typename U,
            typename = std::enable_if_t<std::is_convertible<U*, T*>::value>>
  lw_shared_ptr& operator=(lw_shared_ptr<U>&& rhs) noexcept {
    if ((*this) != rhs) {
      this->~lw_shared_ptr();
      new (this) lw_shared_ptr(std::forward<lw_shared_ptr<U>>(rhs));
    }

    return (*this);
  };

  /// Checks if `*this` stores a non-null pointer.
  explicit operator bool() const noexcept { return _val != nullptr; }

  /// Compares against nullptr.
  bool operator==(std::nullptr_t) const noexcept { return _val == nullptr; }

  /// Compares against nullptr.
  bool operator!=(std::nullptr_t) const noexcept { return _val != nullptr; }

  /// Compares two lw_shared_ptr<T> objects.
  ///
  /// Note that the comparison operators simply compare pointer values; the
  /// actual objects pointed to are not compared.
  template <typename U>
  bool operator==(const lw_shared_ptr<U>& rhs) const noexcept {
    return _val == rhs._val;
  }

  /// Compares two lw_shared_ptr<T> objects.
  ///
  /// Note that the comparison operators simply compare pointer values; the
  /// actual objects pointed to are not compared.
  template <typename U>
  bool operator!=(const lw_shared_ptr<U>& rhs) const noexcept {
    return _val != rhs._val;
  }

  /// Compares two lw_shared_ptr<T> objects.
  ///
  /// Note that the comparison operators simply compare pointer values; the
  /// actual objects pointed to are not compared.
  template <typename U>
  bool operator<(const lw_shared_ptr<U>& rhs) const noexcept {
    return _val < rhs._val;
  }

  /// Compares two lw_shared_ptr<T> objects.
  ///
  /// Note that the comparison operators simply compare pointer values; the
  /// actual objects pointed to are not compared.
  template <typename U>
  bool operator<=(const lw_shared_ptr<U>& rhs) const noexcept {
    return _val <= rhs._val;
  }

  /// Compares two lw_shared_ptr<T> objects.
  ///
  /// Note that the comparison operators simply compare pointer values; the
  /// actual objects pointed to are not compared.
  template <typename U>
  bool operator>(const lw_shared_ptr<U>& rhs) const noexcept {
    return _val > rhs._val;
  }

  /// Compares two lw_shared_ptr<T> objects.
  ///
  /// Note that the comparison operators simply compare pointer values; the
  /// actual objects pointed to are not compared.
  template <typename U>
  bool operator>=(const lw_shared_ptr<U>& rhs) const noexcept {
    return _val >= rhs._val;
  }

  /// Releases the ownership of the managed object, if any.
  ///
  /// After the call, *this manages no object.
  void reset() noexcept { (*this) = {}; }

  /// Replaces the managed object with one constructed with the arguments
  /// provided
  template <typename... Args>
  void reset(Args&&... args) noexcept(
      std::is_nothrow_constructible<T, Args...>::value) {
    (*this) = T(std::forward<Args>(args)...);
  }

  /// Swaps the managed objects
  void swap(lw_shared_ptr& rhs) noexcept {
    using std::swap;
    swap(_val, rhs._val);
    swap(_count, rhs._count);
  }

  /// Dereferences the stored pointer
  T& operator*() const noexcept { return *_val; }

  /// Dereferences the stored pointer
  T* operator->() const { return _val; }

  /// Returns the stored pointer or nullptr if the shared_ptr is empty.
  T* get() const { return _val; }

  /// Returns the number of different shared_ptr instances (this included)
  /// managing the current object. If there is no managed object, ​0​ is
  /// returned.
  unsigned use_count() const noexcept {
    if (_val != nullptr) {
      return *_count + 1;
    }

    return 0;
  }

 private:
  T* _val{};           ///< Pointer to the managed object storage
  unsigned* _count{};  ///< Pointer to the reference count

  // Allow access to other lw_shared_ptr internals.  This is needed for
  // the base class conversions.
  template <typename U>
  friend class lw_shared_ptr;
};

/// Swaps the managed objects between two lw_shared_ptrs
template <typename T>
void swap(lw_shared_ptr<T>& lhs, lw_shared_ptr<T>& rhs) noexcept {
  lhs.swap(rhs);
}

/// Constructs an object of type T and wraps it in a lw_shared_ptr using args as
/// the parameter list for the constructor of T.
template <typename T, typename... Args>
lw_shared_ptr<T> make_lw_shared(Args&&... args) noexcept(
    std::is_nothrow_constructible<T, Args...>::value) {
  return {in_place, std::forward<Args>(args)...};
}

template <typename T, typename U>
lw_shared_ptr<T> lw_static_pointer_cast(const lw_shared_ptr<U>& r) {
  return lw_shared_ptr<T>{r, static_cast<T*>(r.get())};
}

template <typename T, typename U>
lw_shared_ptr<T> lw_dynamic_pointer_cast(const lw_shared_ptr<U>& r) {
  return lw_shared_ptr<T>{r, dynamic_cast<T*>(r.get())};
}

template <typename T, typename U>
lw_shared_ptr<T> lw_const_pointer_cast(const lw_shared_ptr<U>& r) {
  return lw_shared_ptr<T>{r, const_cast<T*>(r.get())};
}

template <typename T, typename U>
lw_shared_ptr<T> lw_reinterpret_pointer_cast(const lw_shared_ptr<U>& r) {
  return lw_shared_ptr<T>{r, reinterpret_cast<T*>(r.get())};
}
