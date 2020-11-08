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

#include "pump/config.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define OS_WINDOWS
#elif defined(__linux__) || defined(__unix__)
#define OS_LINUX
#endif

#if defined(__CYGWIN__)
#define OS_CYGWIN
#endif

#if defined(PUMP_HAVE_WINSOCK)
#if (_WIN32_WINNT < 0x0600)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <windows.h>
#endif

#if defined( _MSC_VER)
#pragma warning(disable : 4251)
#endif

#include <string.h>

#if defined(WITH_STRNCASECMP) && defined(HAVE_STRNGS_HEADER)
#include <strings.h>
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

#if defined(WITH_STRCPYS)
#define pump_strncpy strcpy_s
#elif defined(WITH_STRNCPY)
#define pump_strncpy strncpy
#endif

#if defined(WITH_SPRINTFS)
#define pump_snprintf sprintf_s
#elif defined(WITH_SNPRINTF)
#define pump_snprintf snprintf
#endif

#if defined(WITH_STRNICMP)
#define pump_strncasecmp _strnicmp
#elif defined(WITH_SNPRINTF) 
#define pump_strncasecmp strncasecmp
#endif

#if defined(WITH_SWTCHTOTHREAD)
#define pump_sched_yield SwitchToThread
#elif defined(WITH_SCHEDYIELD)
#define pump_sched_yield sched_yield
#endif

#endif