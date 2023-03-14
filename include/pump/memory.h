/*
 * Copyright (C) 2015-2018 ZhengHaiTao <ming8ren@163.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef pump_memory_h
#define pump_memory_h

#include <cstdint>
#include <cstddef>
#include <stdlib.h>
#include <type_traits>

#include <pump/platform.h>

#if defined(PUMP_HAVE_JEMALLOC)
#define JEMALLOC_NO_RENAME
#include <jemalloc/jemalloc.h>
#endif

#define pump_cache_line_size 64

#define pump_alignas(alignment) alignas(alignment)

#define pump_cache_line_alignas pump_alignas(pump_cache_line_size)

#if defined(PUMP_HAVE_JEMALLOC)
#define pump_free je_free
#define pump_malloc je_malloc
#define pump_realloc je_realloc
#else
#define pump_free ::free
#define pump_malloc ::malloc
#define pump_realloc ::realloc
#endif

// Pump object create inline
#define pump_object_create_inline(TYPE, obj, ...) \
    auto obj = (TYPE *)pump_malloc(sizeof(TYPE)); \
    if (pump_unlikely(obj != nullptr)) {          \
        new (obj) TYPE(__VA_ARGS__);               \
    }                                             \
    void(0)

// Pump object destroy inline
#define pump_object_destroy_inline(obj, TYPE) \
    if (pump_likely(obj != nullptr)) {        \
        obj->~TYPE();                         \
        pump_free(obj);                       \
    }                                         \
    void(0)

template <typename T, typename... ArgTypes>
pump_inline T *pump_object_create(ArgTypes... args) {
    T *p = (T *)pump_malloc(sizeof(T));
    if (pump_unlikely(p == nullptr)) {
        return nullptr;
    }
    return new (p) T(args...);
}

template <typename T>
pump_inline void pump_object_destroy(T *obj) {
    if (pump_likely(obj != nullptr)) {
        obj->~T();
        pump_free(obj);
    }
}

#if defined(OS_WINDOWS)
// libstdc++ forgot to add it to std:: for a while
typedef ::max_align_t pump_max_align_t;
#else
// Others (e.g. MSVC) insist it can *only* be accessed via std::
typedef std::max_align_t pump_max_align_t;
#endif

// Some platforms have incorrectly set max_align_t to a type with < 8 bytes
// alignment even while supporting 8-byte aligned scalar values (*cough*
// 32-bit iOS). Work around this with our own union.
typedef union {
    pump_max_align_t x;
    long long y;
    void *z;
} pump_max_align_un;

template <typename U>
pump_inline char *pump_align_for(char *ptr) {
    const std::size_t alignment = std::alignment_of<U>::value;
    return ptr + (alignment - (reinterpret_cast<std::uintptr_t>(ptr) % alignment)) % alignment;
}

template <typename T>
pump_inline void *pump_aligned_malloc(size_t size) {
    if (std::alignment_of<T>::value <= std::alignment_of<pump_max_align_un>::value) {
        return pump_malloc(size);
    }
    size_t alignment = std::alignment_of<T>::value;
    void *raw = pump_malloc(size + alignment - 1 + sizeof(void *));
    if (raw == nullptr) {
        return nullptr;
    }
    char *ptr = pump_align_for<T>(reinterpret_cast<char *>(raw) + sizeof(void *));
    *(reinterpret_cast<void **>(ptr) - 1) = raw;
    return ptr;
}

template <typename T>
pump_inline void pump_aligned_free(void *ptr) {
    if (std::alignment_of<T>::value <= std::alignment_of<pump_max_align_un>::value) {
        return pump_free(ptr);
    }
    pump_free(ptr ? *(reinterpret_cast<void **>(ptr) - 1) : nullptr);
}

template <typename T, typename... ArgTypes>
pump_inline T *pump_aligned_object_create(ArgTypes... args) {
    T *p = (T *)pump_aligned_malloc<T>(sizeof(T));
    if (pump_unlikely(p == nullptr)) {
        return nullptr;
    }
    return new (p) T(args...);
}

template <typename T>
pump_inline void pump_aligned_object_destroy(T *obj) {
    if (pump_likely(obj != nullptr)) {
        obj->~T();
        pump_aligned_free<T>(obj);
    }
}

#endif
