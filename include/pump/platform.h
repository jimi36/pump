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

#ifndef pump_platform_h
#define pump_platform_h

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define OS_WINDOWS
#elif defined(__linux__) || defined(__unix__)
#define OS_LINUX
#endif

#if defined(OS_WINDOWS)
#include <winsock2.h>
#include <windows.h>
#pragma warning(disable : 4251)
#endif

#if defined(OS_WINDOWS) && defined(pump_EXPORTS)
#define LIB_PUMP __declspec(dllexport)
#else
#define LIB_PUMP
#endif

#if defined(OS_WINDOWS)
#define PUMP_INLINE __forceinline
#elif defined(OS_LINUX)
#define PUMP_INLINE __inline__ __attribute__((always_inline))
#else
#define PUMP_INLINE
#endif

#define PUMP_ENDIAD_KEY 0x01
#if PUMP_ENDIAD_KEY == 0x0201 >> 8
#if !defined(BIG_ENDIAN)
#define BIG_ENDIAN
#endif
#elif PUMP_ENDIAD_KEY == 0x0102 >> 8
#if !defined(LITTLE_ENDIAN)
#define LITTLE_ENDIAN
#endif
#else
#error "Unknow endian"
#endif

#if defined(__GNUC__)
#define PUMP_LIKELY(x) __builtin_expect((x), true)
#define PUMP_UNLIKELY(x) __builtin_expect((x), false)
#else
#define PUMP_LIKELY(x) (x)
#define PUMP_UNLIKELY(x) (x)
#endif

#if defined(OS_WINDOWS)
#define pump_strncpy strcpy_s
#define pump_snprintf sprintf_s
#define pump_strncasecmp _strnicmp
#define pump_sched_yield SwitchToThread
#elif defined(__GNUC__)
#define pump_strncpy strncpy
#define pump_snprintf snprintf
#define pump_strncasecmp strncasecmp
#define pump_sched_yield sched_yield
#endif

#endif