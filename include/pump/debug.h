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

#ifndef pump_defines_h
#define pump_defines_h

#include <assert.h>

#include "pump/platform.h"

// Pump assert
#define PUMP_ASSERT(x) assert(x)
// Pump static assert
#define PUMP_STATIC_ASSERT(x, msg) static_assert((x), msg)

// Pump abort
#define PUMP_ABORT() abort()

// Pump abort with log
#define PUMP_ABORT_WITH_LOG(x, log) \
    if (PUMP_UNLIKELY(x)) { \
        PUMP_ERR_LOG(log); \
        PUMP_ABORT(); \
    }

// Pump debug check
#if defined(NDEBUG)
#define PUMP_DEBUG_CHECK(x) x
#else
#define PUMP_DEBUG_CHECK(x) \
    if (PUMP_UNLIKELY(!x)) { \
        PUMP_ASSERT(false); \
    }
#endif

// Pump debug condition fail
#define PUMP_DEBUG_FAILED(c, log, x) \
    if (PUMP_UNLIKELY(c)) { \
        PUMP_WARN_LOG(log); \
        x; \
    }

#if defined(PUMP_HAVE_DEBUG_LOG)
#define PUMP_ERR_LOG(fmt, ...) \
    printf("\033[1;31m[Error][%s][%s:%d] " fmt "\n\033[0m", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define PUMP_WARN_LOG(fmt, ...) \
    printf("\033[1;33m[Warn][%s][%s:%d] " fmt "\n\033[0m", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define PUMP_DEBUG_LOG(fmt, ...) \
    printf("\033[1;37m[Debug][%s][%s:%d] " fmt "\n\033[0m", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define PUMP_ERR_LOG(...) \
    printf("\033[1;31m[Error][%s][%s:%d] " fmt "\n\033[0m", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define PUMP_WARN_LOG(...) \
    printf("\033[1;33m[Warn][%s][%s:%d] " fmt "\n\033[0m", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define PUMP_DEBUG_LOG(...) void(0)
#endif

#endif
