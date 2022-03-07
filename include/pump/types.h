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

#include <memory>
#include <functional>

#include "pump/platform.h"

// For gnutls
#if defined(OS_WINDOWS) && defined(PUMP_HAVE_GNUTLS)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

// For function callback
#define pump_bind std::bind
#define pump_function std::function
using namespace std::placeholders;

// For smart pointer
#define DEFINE_SMART_POINTERS(class_name)                \
    typedef std::weak_ptr<class_name> class_name##_wptr; \
    typedef std::shared_ptr<class_name> class_name##_sptr;

// For float types
typedef float float32_t;
typedef double float64_t;

#endif
