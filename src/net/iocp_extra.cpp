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

#include "pump/memory.h"
#include "pump/net/iocp_extra.h"

namespace pump {
namespace net {

#if defined(PUMP_HAVE_IOCP)
    struct iocp_extra_function {
        iocp_extra_function() noexcept {
            accept_ex = nullptr;
            connect_ex = nullptr;
            get_accepted_addrs = nullptr;
        }

        LPFN_ACCEPTEX accept_ex;
        LPFN_CONNECTEX connect_ex;
        LPFN_GETACCEPTEXSOCKADDRS get_accepted_addrs;
    };
    DEFINE_RAW_POINTER_TYPE(iocp_extra_function);

    void_ptr get_extension_function(int32 fd, const GUID *id) {
        DWORD bytes = 0;
        void_ptr ptr = nullptr;
        WSAIoctl(fd,
                 SIO_GET_EXTENSION_FUNCTION_POINTER,
                 (GUID *)id,
                 sizeof(*id),
                 &ptr,
                 sizeof(ptr),
                 &bytes,
                 nullptr,
                 nullptr);

        return ptr;
    }

    void_ptr new_iocp_extra_function(int32 fd) {
        GUID guid_accept_ex = WSAID_ACCEPTEX;
        LPFN_ACCEPTEX accept_ex =
            (LPFN_ACCEPTEX)get_extension_function(fd, &guid_accept_ex);
        GUID guid_get_acceptex_sockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
        LPFN_GETACCEPTEXSOCKADDRS get_accepted_addrs =
            (LPFN_GETACCEPTEXSOCKADDRS)get_extension_function(
                fd, &guid_get_acceptex_sockaddrs);
        GUID guid_connect_ex = WSAID_CONNECTEX;
        LPFN_CONNECTEX connect_ex =
            (LPFN_CONNECTEX)get_extension_function(fd, &guid_connect_ex);
        if (accept_ex == nullptr || get_accepted_addrs == nullptr ||
            connect_ex == nullptr)
            return nullptr;

        auto handler = object_create<iocp_extra_function>();
        handler->accept_ex = accept_ex;
        handler->connect_ex = connect_ex;
        handler->get_accepted_addrs = get_accepted_addrs;

        return handler;
    }

    void delete_iocp_extra_function(void_ptr fns) {
        if (fns)
            object_delete(iocp_extra_function_ptr(fns));
    }

    void_ptr get_iocp_accpet_fn(void_ptr fns) {
        if (fns) {
            return (void_ptr)iocp_extra_function_ptr(fns)->accept_ex;
        }
        return nullptr;
    }

    void_ptr get_accept_addrs_fn(void_ptr fns) {
        if (fns) {
            return (void_ptr)iocp_extra_function_ptr(fns)->get_accepted_addrs;
        }
        return nullptr;
    }

    void_ptr get_iocp_connect_fn(void_ptr fns) {
        if (fns) {
            return (void_ptr)iocp_extra_function_ptr(fns)->connect_ex;
        }
        return nullptr;
    }
#endif

}  // namespace net
}  // namespace pump