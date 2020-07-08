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

#include "pump/config.h"
#include "pump/platform.h"

#if defined(USE_JEMALLOC)
extern "C" {
	#include <jemalloc/jemalloc.h>
}
#endif

#if defined(USE_JEMALLOC)
	#define pump_malloc  je_malloc
	#define pump_realloc je_realloc
	#define pump_free    je_free
#else
	#define pump_malloc  malloc
	#define pump_realloc realloc
	#define pump_free    free
#endif

#define OC_TEMPLATE_LIST_0 typename T
#define OC_TEMPLATE_LIST_1 OC_TEMPLATE_LIST_0, typename A1
#define OC_TEMPLATE_LIST_2 OC_TEMPLATE_LIST_1, typename A2
#define OC_TEMPLATE_LIST_3 OC_TEMPLATE_LIST_2, typename A3
#define OC_TEMPLATE_LIST_4 OC_TEMPLATE_LIST_3, typename A4
#define OC_TEMPLATE_LIST_5 OC_TEMPLATE_LIST_4, typename A5
#define OC_TEMPLATE_LIST_6 OC_TEMPLATE_LIST_5, typename A6
#define OC_TEMPLATE_LIST_7 OC_TEMPLATE_LIST_6, typename A7
#define OC_TEMPLATE_LIST_8 OC_TEMPLATE_LIST_7, typename A8
#define OC_TEMPLATE_LIST_9 OC_TEMPLATE_LIST_8, typename A9

#define OC_PARAMS_LIST_0
#define OC_PARAMS_LIST_1 A1 a1
#define OC_PARAMS_LIST_2 OC_PARAMS_LIST_1, A2 a2
#define OC_PARAMS_LIST_3 OC_PARAMS_LIST_2, A3 a3
#define OC_PARAMS_LIST_4 OC_PARAMS_LIST_3, A4 a4
#define OC_PARAMS_LIST_5 OC_PARAMS_LIST_4, A5 a5
#define OC_PARAMS_LIST_6 OC_PARAMS_LIST_5, A6 a6
#define OC_PARAMS_LIST_7 OC_PARAMS_LIST_6, A7 a7
#define OC_PARAMS_LIST_8 OC_PARAMS_LIST_7, A8 a8
#define OC_PARAMS_LIST_9 OC_PARAMS_LIST_8, A9 a9

#define OC_ARGS_LIST_0
#define OC_ARGS_LIST_1 a1
#define OC_ARGS_LIST_2 OC_ARGS_LIST_1, a2
#define OC_ARGS_LIST_3 OC_ARGS_LIST_2, a3
#define OC_ARGS_LIST_4 OC_ARGS_LIST_3, a4
#define OC_ARGS_LIST_5 OC_ARGS_LIST_4, a5
#define OC_ARGS_LIST_6 OC_ARGS_LIST_5, a6
#define OC_ARGS_LIST_7 OC_ARGS_LIST_6, a7
#define OC_ARGS_LIST_8 OC_ARGS_LIST_7, a8
#define OC_ARGS_LIST_9 OC_ARGS_LIST_8, a9

// Build object create functions
#define BUILD_OBJECT_CREATE_FUNCTION(N) \
	template <OC_TEMPLATE_LIST_##N> \
	PUMP_INLINE T* object_create(OC_PARAMS_LIST_##N) \
	{ \
		T* p = (T*)pump_malloc(sizeof(T)); \
		if (PUMP_UNLIKELY(p == nullptr)) \
			return nullptr; \
		else \
			return new (p) T(OC_ARGS_LIST_##N); \
	}
BUILD_OBJECT_CREATE_FUNCTION(0)
BUILD_OBJECT_CREATE_FUNCTION(1)
BUILD_OBJECT_CREATE_FUNCTION(2)
BUILD_OBJECT_CREATE_FUNCTION(3)
BUILD_OBJECT_CREATE_FUNCTION(4)
BUILD_OBJECT_CREATE_FUNCTION(5)
BUILD_OBJECT_CREATE_FUNCTION(6)
BUILD_OBJECT_CREATE_FUNCTION(7)
BUILD_OBJECT_CREATE_FUNCTION(8)
BUILD_OBJECT_CREATE_FUNCTION(9)

// Inline object create
#define INLINE_OBJECT_CREATE(obj, TYPE, args) \
	TYPE* obj = (TYPE*)pump_malloc(sizeof(TYPE)); \
	if (PUMP_UNLIKELY(obj != nullptr)) \
		new (obj) TYPE##args;

template <typename T>
PUMP_INLINE void object_delete(T *p)
{
	if (PUMP_UNLIKELY(p == nullptr))
		return;
	// Deconstruct object
	p->~T();
	// Free memory
	pump_free(p);
}

// Try to lock shared pointer and store to raw pointor
#define PUMP_LOCK_SPOINTER(p, sp) \
	auto p##_locker = sp; \
	auto p = p##_locker.get()

// Try to lock weak pointer and store to raw pointor
#define PUMP_LOCK_WPOINTER(p, wp) \
	auto p##_locker = wp.lock(); \
	auto p = p##_locker.get()

#endif