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

// Pump assert
#define PUMP_ASSERT(x) assert(x)
// Pump static assert
#define PUMP_STATIC_ASSERT(x, msg) static_assert((x), msg)

// Pump abort
#define PUMP_ABORT() abort()

// Pump abort with log
#define PUMP_ABORT_WITH_LOG(x, log) \
    if (pump_unlikely(x)) {         \
        PUMP_ERR_LOG(log);          \
        PUMP_ABORT();               \
    }

#if defined(PUMP_HAVE_DEBUG_LOG)
#define PUMP_ERR_LOG(fmt, ...)                              \
    printf("\033[1;31m[Error][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                        \
           __FUNCTION__,                                    \
           __LINE__,                                        \
           ##__VA_ARGS__)
#define PUMP_WARN_LOG(fmt, ...)                            \
    printf("\033[1;33m[Warn][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                       \
           __FUNCTION__,                                   \
           __LINE__,                                       \
           ##__VA_ARGS__)
#define PUMP_DEBUG_LOG(fmt, ...)                            \
    printf("\033[1;37m[Debug][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                        \
           __FUNCTION__,                                    \
           __LINE__,                                        \
           ##__VA_ARGS__)
#else
#define PUMP_ERR_LOG(fmt, ...)                              \
    printf("\033[1;31m[Error][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                        \
           __FUNCTION__,                                    \
           __LINE__,                                        \
           ##__VA_ARGS__)
#define PUMP_WARN_LOG(fmt, ...)                            \
    printf("\033[1;33m[Warn][%s][%s:%d] " fmt "\n\033[0m", \
           __FILE__,                                       \
           __FUNCTION__,                                   \
           __LINE__,                                       \
           ##__VA_ARGS__)
#define PUMP_DEBUG_LOG(fmt, ...) void(0)
#endif

#endif
