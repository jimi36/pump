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

#ifndef pump_net_error_h
#define pump_net_error_h

#include "pump/config.h"

#if defined(PUMP_HAVE_WINSOCK)
#define LANE_EINTR WSAEINTR                      // 10004
#define LANE_EBADF WSAEBADF                      // 10009
#define LANE_EACCES WSAEACCES                    // 10013
#define LANE_EFAULT WSAEFAULT                    // 10014
#define LANE_EINVAL WSAEINVAL                    // 10022
#define LANE_EMFILE WSAEMFILE                    // 10024
#define LANE_EWOULDBLOCK WSAEWOULDBLOCK          // 10035
#define LANE_EINPROGRESS WSAEINPROGRESS          // 10036
#define LANE_EALREADY WSAEALREADY                // 10037
#define LANE_ENOTSOCK WSAENOTSOCK                // 10038
#define LANE_EDESTADDRREQ WSAEDESTADDRREQ        // 10039
#define LANE_EMSGSIZE WSAEMSGSIZE                // 10040
#define LANE_EPROTOTYPE WSAEPROTOTYPE            // 10041
#define LANE_ENOPROTOOPT WSAENOPROTOOPT          // 10042
#define LANE_EPROTONOSUPPORT WSAEPROTONOSUPPORT  // 10043
#define LANE_ESOCKTNOSUPPORT WSAESOCKTNOSUPPORT  // 10044
#define LANE_EOPNOTSUPP WSAEOPNOTSUPP            // 10045
#define LANE_EPFNOSUPPORT WSAEPFNOSUPPORT        // 10046
#define LANE_EAFNOSUPPORT WSAEAFNOSUPPORT        // 10047
#define LANE_EADDRINUSE WSAEADDRINUSE            // 10048
#define LANE_EADDRNOTAVAIL WSAEADDRNOTAVAIL      // 10049
#define LANE_ENETDOWN WSAENETDOWN                // 10050
#define LANE_ENETUNREACH WSAENETUNREACH          // 10051
#define LANE_ENETRESET WSAENETRESET              // 10052
#define LANE_ECONNABORTED WSAECONNABORTED        // 10053
#define LANE_ECONNRESET WSAECONNRESET            // 10054
#define LANE_ENOBUFS WSAENOBUFS                  // 10055
#define LANE_EISCONN WSAEISCONN                  // 10056
#define LANE_ENOTCONN WSAENOTCONN                // 10057
#define LANE_ESHUTDOWN WSAESHUTDOWN              // 10058
#define LANE_ETOOMANYREFS WSAETOOMANYREFS        // 10059
#define LANE_ETIMEDOUT WSAETIMEDOUT              // 10060
#define LANE_ECONNREFUSED WSAECONNREFUSED        // 10061
#define LANE_ELOOP WSAELOOP                      // 10062
#define LANE_ENAMETOOLONG WSAENAMETOOLONG        // 10063
#define LANE_EHOSTDOWN WSAEHOSTDOWN              // 10064
#define LANE_EHOSTUNREACH WSAEHOSTUNREACH        // 10065
#define LANE_HOST_NOT_FOUND WSAHOST_NOT_FOUND    // 10004
#else
#define LANE_EINTR EINTR                      // 4 Interrupted system call
#define LANE_EBADF EBADF                      // 9 Bad file number
#define LANE_EACCES EACCES                    // 13 Permission denied
#define LANE_EFAULT EFAULT                    // 14 Bad address
#define LANE_EINVAL EINVAL                    // 22 Invalid argument
#define LANE_EMFILE EMFILE                    // 24 Too many open files
#define LANE_EWOULDBLOCK EWOULDBLOCK          // 11 Operation would block as EAGAIN
#define LANE_EINPROGRESS EINPROGRESS          // 115 Operation now in progress
#define LANE_EALREADY EALREADY                // 114 Operation already in progress
#define LANE_ENOTSOCK ENOTSOCK                // 88 Socket operation on non-socket
#define LANE_EDESTADDRREQ EDESTADDRREQ        // 89 Destination address required
#define LANE_EMSGSIZE EMSGSIZE                // 90 Message too long
#define LANE_EPROTOTYPE EPROTOTYPE            // 91 Protocol wrong type for socket
#define LANE_ENOPROTOOPT ENOPROTOOPT          // 92 Protocol not available
#define LANE_EPROTONOSUPPORT EPROTONOSUPPORT  // 93 Protocol not supported
#define LANE_ESOCKTNOSUPPORT ESOCKTNOSUPPORT  // 94 Socket type not supported
#define LANE_EOPNOTSUPP EOPNOTSUPP  // 95 Operation not supported on transport endpoint
#define LANE_EPFNOSUPPORT EPFNOSUPPORT    // 96 Protocol family not supported
#define LANE_EAFNOSUPPORT EAFNOSUPPORT    // 97 Address family not supported by protocol
#define LANE_EADDRINUSE EADDRINUSE        // 98 Address already in use
#define LANE_EADDRNOTAVAIL EADDRNOTAVAIL  // 99 Cannot assign requested address
#define LANE_ENETDOWN ENETDOWN            // 100 Network is down
#define LANE_ENETUNREACH ENETUNREACH      // 101 Network is unreachable
#define LANE_ENETRESET ENETRESET        // 102 Network dropped connection because of reset
#define LANE_ECONNABORTED ECONNABORTED  // 103 Software caused connection abort
#define LANE_ECONNRESET ECONNRESET      // 104 Connection reset by peer
#define LANE_ENOBUFS ENOBUFS            // 105 No buffer space available
#define LANE_EISCONN EISCONN            // 106 Transport endpoint is already connected
#define LANE_ENOTCONN ENOTCONN          // 107 Transport endpoint is not connected
#define LANE_ESHUTDOWN ESHUTDOWN  // 108 Cannot send after transport endpoint shutdown
#define LANE_ETOOMANYREFS ETOOMANYREFS      // 109 Too many references: cannot splice
#define LANE_ETIMEDOUT ETIMEDOUT            // 110 Connection timed out
#define LANE_ECONNREFUSED ECONNREFUSED      // 111 Connection refused
#define LANE_ELOOP ELOOP                    // 40 Too many symbolic links encountered
#define LANE_ENAMETOOLONG ENAMETOOLONG      // 36 File name too long
#define LANE_EHOSTDOWN EHOSTDOWN            // 112 Host is down
#define LANE_EHOSTUNREACH EHOSTUNREACH      // 113 No route to host
#define LANE_HOST_NOT_FOUND HOST_NOT_FOUND  // 1 Host not found
#endif

#endif