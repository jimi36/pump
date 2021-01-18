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

namespace pump {
namespace net {

#if defined(PUMP_HAVE_IOCP)

    union win_socket {
        HANDLE  h;
        int32_t i;
    };

    PUMP_INLINE win_socket new_win_socket() {
        win_socket fd; 
        fd.h = 0;
        return fd;
    }

    net::iocp_handler g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

    net::iocp_handler get_iocp_handler() {
        return g_iocp;
    }

    int32_t create_iocp_socket(int32_t domain, int32_t type, iocp_handler iocp) {
        win_socket fd = new_win_socket();
        fd.i = (int32_t)::WSASocket(domain, type, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);

        if (fd.i == SOCKET_ERROR ||
            CreateIoCompletionPort(fd.h, iocp, 0, 0) == NULL) {
            PUMP_DEBUG_LOG("net: create_iocp_socket failed %d", last_errno());
            close(fd.i);
            return -1;
        }

        return fd.i;
    }

    bool post_iocp_accept(void_ptr ex_fns, iocp_task_ptr task) {
        auto accept_ex = (LPFN_ACCEPTEX)get_iocp_accpet_fn(ex_fns);
        if (!accept_ex) {
            PUMP_DEBUG_LOG("net: post_iocp_accept failed for invalid accept_ex function");
            return false;
        }

        task->add_link();
        {
            DWORD bytes = 0;
            DWORD addrlen = sizeof(sockaddr_in) + 16;
            if (accept_ex(task->fd_,
                          task->un_.client_fd,
                          task->buf_.buf,
                          0,
                          addrlen,
                          addrlen,
                          &bytes,
                          &(task->ol)) == TRUE ||
                net::last_errno() == ERROR_IO_PENDING) {
                return true;
            }
        }
        task->sub_link();

        PUMP_DEBUG_LOG("net: post_iocp_accept failed %d", last_errno());

        return false;
    }

    bool get_iocp_client_address(void_ptr ex_fns,
                                 iocp_task_ptr task,
                                 sockaddr **local,
                                 int32_t *llen,
                                 sockaddr **remote,
                                 int32_t *rlen) {
        auto get_addrs = (LPFN_GETACCEPTEXSOCKADDRS)get_accept_addrs_fn(ex_fns);
        if (!get_addrs) {
            PUMP_DEBUG_LOG("net: get_iocp_accepted_address failed with invalid get_addrs function");
            return false;
        }

        win_socket fd = new_win_socket();
        fd.i = task->fd_;
        DWORD addrlen = sizeof(sockaddr_in) + 16;
        get_addrs(task->buf_.buf, 0, addrlen, addrlen, local, llen, remote, rlen);
        if (setsockopt(task->un_.client_fd,
                       SOL_SOCKET,
                       SO_UPDATE_ACCEPT_CONTEXT,
                       (block_t*)&fd.h,
                       sizeof(fd.h)) == SOCKET_ERROR) {
            PUMP_DEBUG_LOG("net: get_iocp_accepted_address failed %d", last_errno());
            return false;
        }
        return true;
    }

    bool post_iocp_connect(void_ptr ex_fns,
                           iocp_task_ptr task,
                           const sockaddr *addr,
                           int32_t addrlen) {
        auto connect_ex = (LPFN_CONNECTEX)get_iocp_connect_fn(ex_fns);
        if (!connect_ex) {
            PUMP_DEBUG_LOG("net: post_iocp_connect fialed with invalid connect_ex function");
            return false;
        }

        task->add_link();
        {
            if (connect_ex(task->fd_, addr, addrlen, NULL, 0, NULL, &(task->ol)) == TRUE &&
                setsockopt(task->fd_, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == 0) {
                return true;
            }
            if (last_errno() == WSA_IO_PENDING) {
                return true;
            }
        }
        task->sub_link();

        PUMP_DEBUG_LOG("net: post_iocp_connect failed %d", last_errno());

        return false;
    }

    bool post_iocp_read(iocp_task_ptr task) {
        task->add_link();
        {
            DWORD flags = 0;
            if (::WSARecv(task->fd_, &task->buf_, 1, NULL, &flags, &(task->ol), NULL) != SOCKET_ERROR ||
                last_errno() == WSA_IO_PENDING) {
                return true;
            }
        }
        task->sub_link();

        PUMP_DEBUG_LOG("net: post_iocp_read failed %d", last_errno());

        return false;
    }

    bool post_iocp_read_from(iocp_task_ptr task) {
        task->add_link();
        {
            DWORD flags = 0;
            task->un_.ip.addr_len = sizeof(task->un_.ip.addr);
            if (::WSARecvFrom(task->fd_,
                              &task->buf_,
                              1,
                              NULL,
                              &flags,
                              (sockaddr*)task->un_.ip.addr,
                              &task->un_.ip.addr_len,
                              &task->ol,
                              NULL) != SOCKET_ERROR ||
                last_errno() == WSA_IO_PENDING) {
                return true;
            }
        }
        task->sub_link();

        PUMP_DEBUG_LOG("net: post_iocp_read_from failed %d", last_errno());

        return false;
    }

    bool post_iocp_send(iocp_task_ptr task) {
        task->add_link();
        {
            if (::WSASend(task->fd_,
                          &task->buf_,
                          1,
                          NULL,
                          0,
                          (WSAOVERLAPPED*)&task->ol,
                          NULL) != SOCKET_ERROR ||
                last_errno() == WSA_IO_PENDING) {
                return true;
            }
        }
        task->sub_link();

        PUMP_DEBUG_LOG("net: post_iocp_read_from failed %d", last_errno());

        return false;
    }
#endif

}  // namespace net
}  // namespace pump