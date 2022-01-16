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

#include <atomic>

#include "pump/debug.h"
#include "pump/memory.h"
#include "pump/net/iocp.h"
#include "pump/net/socket.h"

#if defined(PUMP_HAVE_IOCP)
FnNtCreateFile NtCreateFile = nullptr;
FnNtDeviceIoControlFile NtDeviceIoControlFile = nullptr;
FnNtCancelIoFileEx NtCancelIoFileEx = nullptr;
#endif

namespace pump {
namespace net {

    pump_socket get_base_socket(pump_socket fd) {
#if defined(PUMP_HAVE_IOCP)
        DWORD bytes;
        SOCKET base_socket;
        if (WSAIoctl(
                fd,
                SIO_BASE_HANDLE,
                NULL,
                0,
                &base_socket,
                sizeof(base_socket),
                &bytes,
                NULL,
                NULL) != 0) {
            return fd;
        }
        return base_socket;
#else
        return fd;
#endif
    }

}
}


