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

#ifndef pump_debug_h
#define pump_debug_h

#include <assert.h>

#include <pump/build.h>

// Pump assert
#define pump_assert(x) assert(x)
// Pump static assert
#define pump_static_assert(x, msg) static_assert((x), msg)

// Pump abort
#define pump_abort() abort()

// Pump abort with log
#define pump_abort_with_log(fmt, ...) \
    pump_err_log(fmt, ##__VA_ARGS__); \
    pump_abort();

#if defined(PUMP_HAVE_DEBUG_LOG)
#define pump_err_log(fmt, ...)                              \
    printf("\033[1;31m[Error][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                        \
           __FUNCTION__,                                    \
           __LINE__,                                        \
           ##__VA_ARGS__)
#define pump_warn_log(fmt, ...)                            \
    printf("\033[1;33m[Warn][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                       \
           __FUNCTION__,                                   \
           __LINE__,                                       \
           ##__VA_ARGS__)
#define pump_debug_log(fmt, ...)                            \
    printf("\033[1;37m[Debug][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                        \
           __FUNCTION__,                                    \
           __LINE__,                                        \
           ##__VA_ARGS__)
#else
#define pump_err_log(fmt, ...)                              \
    printf("\033[1;31m[Error][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                        \
           __FUNCTION__,                                    \
           __LINE__,                                        \
           ##__VA_ARGS__)
#define pump_warn_log(fmt, ...)                            \
    printf("\033[1;33m[Warn][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                       \
           __FUNCTION__,                                   \
           __LINE__,                                       \
           ##__VA_ARGS__)
#define pump_debug_log(fmt, ...) void(0)
#endif

#endif
