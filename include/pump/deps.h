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

#ifndef pump_deps_h
#define pump_deps_h

#ifdef WIN32
#	pragma warning(disable:4251)
#	define WIN32_LEAN_AND_MEAN
#endif

#ifdef WIN32
#	ifdef _WIN32_WINNT
#		undef _WIN32_WINNT
#		define _WIN32_WINNT 0x0600
#	endif
#endif

#include <mutex>
#include <thread>
#include <atomic>
#include <memory>
//#include <future>
#include <chrono>  
//#include <string.h>
#include <assert.h>
#include <condition_variable>

#include <map>
//#include <set>
#include <list>
//#include <deque>
#include <vector>
#include <string>
//#include <unordered_set>
#include <unordered_map>

#ifdef WIN32
//#include <time.h>
//#include <process.h>
#include <windows.h>
#else
#include <iconv.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <mswsock.h>
#else
#include <poll.h>
#include <fcntl.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#include "pump/defs.h"
#include "pump/types.h"
#include "function/function.h"

#endif
