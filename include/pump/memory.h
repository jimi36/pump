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

#include "pump/platform.h"

#include <memory>
#include <stdlib.h>

#if defined(PUMP_HAVE_JEMALLOC)
#define JEMALLOC_NO_RENAME
#include <jemalloc/jemalloc.h>
#endif

#if defined(PUMP_HAVE_JEMALLOC)
#define pump_free je_free
#define pump_malloc je_malloc
#define pump_realloc je_realloc
#else
#define pump_free ::free
#define pump_malloc ::malloc
#define pump_realloc ::realloc
#endif

// Inline object create
#define INLINE_OBJECT_CREATE(obj, TYPE, args)      \
    TYPE *obj = (TYPE *)pump_malloc(sizeof(TYPE)); \
    if (PUMP_UNLIKELY(obj != nullptr)) {           \
        new (obj) TYPE args;                       \
    }

// Inline object create
#define INLINE_OBJECT_DELETE(obj, TYPE) \
    if (PUMP_LIKELY(obj != nullptr)) {  \
        obj->~TYPE();                   \
        pump_free(obj);                 \
    }

template <typename T, typename... ArgTypes>
PUMP_INLINE T *object_create(ArgTypes... args) {
    T *p = (T *)pump_malloc(sizeof(T));
    if (PUMP_UNLIKELY(p == nullptr)) {
        return nullptr;
    }
    return new (p) T(args...);
}

template <typename T> PUMP_INLINE void object_delete(T *obj) {
    if (PUMP_LIKELY(obj != nullptr)) {
        obj->~T();
        pump_free(obj);
    }
}

// Try to lock shared pointer and store to raw pointor
//#define PUMP_LOCK_SPOINTER(p, sp)
//    auto p##_locker = sp;
//    auto p = p##_locker.get()

// Try to lock weak pointer and store to raw pointor
//#define PUMP_LOCK_WPOINTER(p, wp)
//    auto p##_locker = wp.lock();
//    auto p = p##_locker.get()

#endif
