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

#if defined(WIN32)
#	define pump_strncpy strcpy_s
#	define pump_snprintf sprintf_s
#	define pump_strncasecmp _strnicmp
#   define pump_sched_yield SwitchToThread
#elif defined(__GNUC__)
#	define pump_strncpy strncpy
#	define pump_snprintf snprintf
#	define pump_strncasecmp strncasecmp
#   define pump_sched_yield sched_yield
#endif

#endif