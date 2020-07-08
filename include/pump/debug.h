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

// Pump assert
#define PUMP_ASSERT(x) assert(x)

// Pump debug assign
#if defined(NDEBUG)
	#define PUMP_DEBUG_ASSIGN(c, d, s) d = s
#else
	#define PUMP_DEBUG_ASSIGN(c, d, s) PUMP_ASSERT(c); d = s
#endif

// Pump debug check
#if defined(NDEBUG)
	#define PUMP_DEBUG_CHECK(x) x
#else
	#define PUMP_DEBUG_CHECK(x) PUMP_ASSERT(x)
#endif

// Pump static assert
#define PUMP_STATIC_ASSERT(x, msg) static_assert((x), msg)

#endif
