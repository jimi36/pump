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

#ifndef pump_config_h
#define pump_config_h

#define PUMP_MAJOR_VERSION 1
#define PUMP_MINOR_VERSION 1
#define PUMP_BUILD_VERSION 4

#define WITHOUT_IOCP
#if defined(WITH_IOCP)
	#define USE_IOCP
#endif

#define WITHOUT_GNUTLS
#if defined(WITH_GNUTLS)
	#define USE_GNUTLS
#endif

#define WITHOUT_JEMALLOC
#if defined(WITH_JEMALLOC)
	#define USE_JEMALLOC
#endif

#endif
