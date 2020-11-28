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

#ifndef pump_types_h
#define pump_types_h

#include "pump/platform.h"

// Import "std::weak_ptr"
// Import "std::shared_ptr"
#include <memory>

#if defined(OS_WINDOWS) && defined(PUMP_HAVE_GNUTLS)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#define DEFINE_RAW_POINTER_TYPE(class_name) \
    typedef class_name *class_name##_ptr;   \
    typedef const class_name *c_##class_name##_ptr;

#define DEFINE_SMART_POINTER_TYPE(class_name)            \
    typedef std::weak_ptr<class_name> class_name##_wptr; \
    typedef std::shared_ptr<class_name> class_name##_sptr;

#define DEFINE_ALL_POINTER_TYPE(class_name) \
    DEFINE_RAW_POINTER_TYPE(class_name)     \
    DEFINE_SMART_POINTER_TYPE(class_name)

DEFINE_ALL_POINTER_TYPE(void);

typedef char block_t;
typedef float float32_t;
typedef double float64_t;

#endif