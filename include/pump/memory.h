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

#include <stdlib.h>

#include "pump/platform.h"

#define pump_except noexcept(false)
#define pump_noexcept noexcept(true)

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
    if (pump_unlikely(obj != nullptr)) {           \
        new (obj) TYPE args;                       \
    }

// Inline object create
#define INLINE_OBJECT_DELETE(obj, TYPE) \
    if (pump_likely(obj != nullptr)) {  \
        obj->~TYPE();                   \
        pump_free(obj);                 \
    }

template <typename T, typename... ArgTypes>
pump_inline T *object_create(ArgTypes... args) {
    T *p = (T *)pump_malloc(sizeof(T));
    if (pump_unlikely(p == nullptr)) {
        return nullptr;
    }
    return new (p) T(args...);
}

template <typename T>
pump_inline void object_delete(T *obj) {
    if (pump_likely(obj != nullptr)) {
        obj->~T();
        pump_free(obj);
    }
}

#endif
