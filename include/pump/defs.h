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

#ifndef pump_defs_h
#define pump_defs_h

// Macro library export qualifier
#if defined(WIN32) && defined(pump_EXPORTS)
#	define LIB_PUMP __declspec(dllexport)
#elif defined(WIN32)
#	define LIB_PUMP __declspec(dllimport)
#else
#	define LIB_PUMP 
#endif

// Macro inline qualifier
#if defined(WIN32)
#	define PUMP_INLINE __forceinline
#elif defined(__GNUC__)
#	define PUMP_INLINE __inline__ __attribute__((always_inline))
#else
#	define PUMP_INLINE
#endif

// Macro pump static qualifier
#define PUMP_STATIC static

// Macro pump const qualifier
#define PUMP_CONST const

// Macro pump constexpr qualifier
#define PUMP_CONST_EXPR constexpr

// Macro pump noexcept qualifier
#define PUMP_NOEXCEPT noexcept
#define PUMP_NOEXCEPT_EXPR(expr) noexcept(expr)

// Macro pump assert qualifier
#define PUMP_ASSERT(x) assert(x)
#define PUMP_ASSERT_EXPR(x, expr) PUMP_ASSERT(x); expr

// Macro pump static assert qualifier
#define PUMP_STATIC_ASSERT(x, msg) static_assert((x), msg)

// Macro pump likely/unlikely hints
#if defined(__GNUC__)
#	define PUMP_LIKELY(x) __builtin_expect((x), true)
#	define PUMP_UNLIKELY(x) __builtin_expect((x), false)
#else
#	define PUMP_LIKELY(x) (x)
#	define PUMP_UNLIKELY(x) (x)
#endif

// Macro debug check expression
#if !defined(NDEBUG)
#	define PUMP_DEBUG_CHECK(expr) PUMP_ASSERT(expr)
#else
#	define PUMP_DEBUG_CHECK(expr) (expr)
#endif

// Macro lock smart pointer to raw pointer
#define PUMP_LOCK_SPOINTER(p, sp) \
	auto p##_locker = sp; \
	auto p = p##_locker.get()

// Macro lock weak pointer to raw pointer
#define PUMP_LOCK_WPOINTER(p, wp) \
	auto p##_locker = wp.lock(); \
	auto p = p##_locker.get()

// Macro system endian
#define PUMP_ENDIAD_KEY 0x01
#if PUMP_ENDIAD_KEY == 0x0102 >> 8
#	if !defined(BIG_ENDIAN)
#		define BIG_ENDIAN
#	endif
#elif PUMP_ENDIAD_KEY == 0x0201 >> 8
#	if !defined(LITTLE_ENDIAN)
#		define LITTLE_ENDIAN
#	endif
#else
#	error "Unknow endian"
#endif

#endif
