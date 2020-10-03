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
    net::iocp_handler g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

    net::iocp_handler get_iocp_handler() {
        return g_iocp;
    }

    struct iocp_task {
        // IOCP overlapped
        WSAOVERLAPPED ol;
        // IOCP buffer
        WSABUF buf;
        // IOCP task type
        int32 type;
        // IOCP processed size
        DWORD processed_size;
        // IOCP fd
        int32 fd;
        // IOCP error code
        int32 ec;
        // Channel notifier
        std::weak_ptr<void> ch_notifier;
        // IO buffer
        toolkit::io_buffer_ptr iob;
        // Ref link count
        std::atomic_int link_cnt;

        union {
            // Client fd for accepting
            int32 client_fd;
            // IP address for connecting
            struct {
                int8 addr[64];
                int32 addr_len;
            } ip;
        } un;

        iocp_task() noexcept
            : type(IOCP_TASK_NONE), processed_size(0), fd(-1), ec(0), iob(nullptr), link_cnt(1) {
            memset(&ol, 0, sizeof(ol));
            memset(&un, 0, sizeof(un));
        }

        PUMP_INLINE void add_link() {
            link_cnt.fetch_add(1);
        }

        PUMP_INLINE void sub_link() {
            if (link_cnt.fetch_sub(1) == 1) {
                __release_resource();
                object_delete(this);
            }
        }

        PUMP_INLINE void __release_resource() {
            if (type == IOCP_TASK_ACCEPT) {
                if (un.client_fd > 0)
                    close(un.client_fd);
            }
            if (iob)
                iob->sub_ref();
        }
    };
    DEFINE_RAW_POINTER_TYPE(iocp_task);

    void_ptr new_iocp_task() {
        return object_create<iocp_task>();
    }

    void reuse_iocp_task(void_ptr task) {
        iocp_task_ptr itask = (iocp_task_ptr)task;
        memset(&itask->ol, 0, sizeof(itask->ol));
    }

    void link_iocp_task(void_ptr task) {
        iocp_task_ptr(task)->add_link();
    }

    void unlink_iocp_task(void_ptr task) {
        iocp_task_ptr(task)->sub_link();
    }

    void set_iocp_task_type(void_ptr task, int32 tp) {
        iocp_task_ptr(task)->type = tp;
    }

    int32 get_iocp_task_type(void_ptr task) {
        return iocp_task_ptr(task)->type;
    }

    void set_iocp_task_fd(void_ptr task, int32 fd) {
        iocp_task_ptr(task)->fd = fd;
    }

    int32 get_iocp_task_fd(void_ptr task) {
        return iocp_task_ptr(task)->fd;
    }

    void set_iocp_task_client_fd(void_ptr task, int32 client_fd) {
        iocp_task_ptr(task)->un.client_fd = client_fd;
    }

    int32 get_iocp_task_client_fd(void_ptr task) {
        return iocp_task_ptr(task)->un.client_fd;
    }

    void set_iocp_task_notifier(void_ptr task, void_wptr ch) {
        PUMP_ASSERT(ch.lock());
        iocp_task_ptr(task)->ch_notifier = ch;
    }

    void_sptr get_iocp_task_notifier(void_ptr task) {
        return iocp_task_ptr(task)->ch_notifier.lock();
    }

    void set_iocp_task_ec(void_ptr task, int32 ec) {
        iocp_task_ptr(task)->ec = ec;
    }

    int32 get_iocp_task_ec(void_ptr task) {
        return iocp_task_ptr(task)->ec;
    }

    void bind_iocp_task_buffer(void_ptr task, toolkit::io_buffer_ptr iob) {
        iob->add_ref();
        iocp_task_ptr(task)->iob = iob;
        if (iob->data_size() > 0) {
            iocp_task_ptr(task)->buf.buf = (block_ptr)iob->data();
            iocp_task_ptr(task)->buf.len = iob->data_size();
        } else {
            iocp_task_ptr(task)->buf.buf = (block_ptr)iob->buffer();
            iocp_task_ptr(task)->buf.len = iob->buffer_size();
        }
    }

    void unbind_iocp_task_buffer(void_ptr task) {
        toolkit::io_buffer_ptr iob = iocp_task_ptr(task)->iob;
        if (PUMP_LIKELY(iob)) {
            iob->sub_ref();
        }
    }

    void update_iocp_task_buffer(void_ptr task) {
        toolkit::io_buffer_ptr iob = iocp_task_ptr(task)->iob;
        if (PUMP_LIKELY(iob)) {
            iocp_task_ptr(task)->buf.len = iob->data_size();
            iocp_task_ptr(task)->buf.buf = (block_ptr)iob->data();
        }
    }

    void set_iocp_task_buffer(void_ptr task, block_ptr b, int32 size) {
        iocp_task_ptr(task)->buf.buf = b;
        iocp_task_ptr(task)->buf.len = (uint32)size;
    }

    void set_iocp_task_processed_size(void_ptr task, int32 size) {
        iocp_task_ptr(task)->processed_size = size;
    }

    int32 get_iocp_task_processed_size(void_ptr task) {
        return iocp_task_ptr(task)->processed_size;
    }

    block_ptr get_iocp_task_processed_data(void_ptr task, int32_ptr size) {
        *size = iocp_task_ptr(task)->processed_size;
        return iocp_task_ptr(task)->buf.buf;
    }

    sockaddr *get_iocp_task_remote_address(void_ptr task, int32_ptr addrlen) {
        *addrlen = iocp_task_ptr(task)->un.ip.addr_len;
        return (sockaddr *)iocp_task_ptr(task)->un.ip.addr;
    }

    int32 create_iocp_socket(int32 domain, int32 type, iocp_handler iocp) {
        int32 fd =
            (int32)::WSASocket(domain, type, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);

        if (fd == SOCKET_ERROR ||
            CreateIoCompletionPort((HANDLE)fd, iocp, 0, 0) == NULL) {
            PUMP_WARN_LOG("create_iocp_socket error: ec=%d", last_errno());
            close(fd);
            return -1;
        }
        return fd;
    }

    bool post_iocp_accept(void_ptr ex_fns, void_ptr task) {
        auto accept_ex = (LPFN_ACCEPTEX)get_iocp_accpet_fn(ex_fns);
        if (!accept_ex) {
            PUMP_WARN_LOG("net::post_iocp_accept: accept_ex invalid");
            return false;
        }

        iocp_task_ptr itask = (iocp_task_ptr)task;
        itask->add_link();
        {
            DWORD bytes = 0;
            DWORD addrlen = sizeof(sockaddr_in) + 16;
            if (accept_ex(itask->fd,
                          itask->un.client_fd,
                          itask->buf.buf,
                          0,
                          addrlen,
                          addrlen,
                          &bytes,
                          &(itask->ol)) == TRUE ||
                net::last_errno() == ERROR_IO_PENDING)
                return true;
        }
        itask->sub_link();

        PUMP_WARN_LOG("net::post_iocp_accept: accept_ex failed with ec=%d", last_errno());

        return false;
    }

    bool get_iocp_accepted_address(void_ptr ex_fns,
                                   void_ptr task,
                                   sockaddr **local,
                                   int32_ptr llen,
                                   sockaddr **remote,
                                   int32_ptr rlen) {
        auto get_addrs = (LPFN_GETACCEPTEXSOCKADDRS)get_accept_addrs_fn(ex_fns);
        if (!get_addrs) {
            PUMP_WARN_LOG("net::get_iocp_accepted_address: get_addrs invalid");
            return false;
        }

        iocp_task_ptr itask = (iocp_task_ptr)task;

        HANDLE fd = (HANDLE)itask->fd;
        DWORD addrlen = sizeof(sockaddr_in) + 16;
        get_addrs(itask->buf.buf, 0, addrlen, addrlen, local, llen, remote, rlen);
        if (setsockopt(itask->un.client_fd,
                       SOL_SOCKET,
                       SO_UPDATE_ACCEPT_CONTEXT,
                       (block_ptr)&fd,
                       sizeof(fd)) == SOCKET_ERROR) {
            PUMP_WARN_LOG("net::get_iocp_accepted_address: setsockopt failed with ec=%d",
                          last_errno());
            return false;
        }
        return true;
    }

    bool post_iocp_connect(void_ptr ex_fns,
                           void_ptr task,
                           const sockaddr *addr,
                           int32 addrlen) {
        auto connect_ex = (LPFN_CONNECTEX)get_iocp_connect_fn(ex_fns);
        if (!connect_ex) {
            PUMP_WARN_LOG("net::post_iocp_connect: connect_ex invalid");
            return false;
        }

        iocp_task_ptr itask = (iocp_task_ptr)task;

        itask->add_link();
        {
            if (connect_ex(itask->fd, addr, addrlen, NULL, 0, NULL, &(itask->ol)) ==
                    TRUE &&
                setsockopt(itask->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) ==
                    0)
                return true;
            if (last_errno() == WSA_IO_PENDING)
                return true;
        }
        itask->sub_link();

        PUMP_WARN_LOG("net::post_iocp_connect: ec=%d", last_errno());

        return false;
    }

    bool post_iocp_read(void_ptr task) {
        iocp_task_ptr itask = (iocp_task_ptr)task;

        itask->add_link();
        {
            DWORD flags = 0;
            if (::WSARecv(itask->fd, &itask->buf, 1, NULL, &flags, &(itask->ol), NULL) !=
                    SOCKET_ERROR ||
                net::last_errno() == WSA_IO_PENDING)
                return true;
        }
        itask->sub_link();

        PUMP_WARN_LOG("net::post_iocp_read: WSARecv failed with ec=%d", last_errno());

        return false;
    }

    bool post_iocp_read_from(void_ptr task) {
        iocp_task_ptr itask = (iocp_task_ptr)task;

        itask->add_link();
        {
            DWORD flags = 0;
            itask->un.ip.addr_len = sizeof(itask->un.ip.addr);
            if (::WSARecvFrom(itask->fd,
                              &itask->buf,
                              1,
                              NULL,
                              &flags,
                              (sockaddr *)itask->un.ip.addr,
                              &itask->un.ip.addr_len,
                              &itask->ol,
                              NULL) != SOCKET_ERROR ||
                net::last_errno() == WSA_IO_PENDING)
                return true;
        }
        itask->sub_link();

        PUMP_WARN_LOG("net::post_iocp_read_from: WSARecvFrom failed with ec=%d",
                      last_errno());

        return false;
    }

    bool post_iocp_send(void_ptr task) {
        iocp_task_ptr itask = (iocp_task_ptr)task;

        itask->add_link();
        {
            if (::WSASend(itask->fd,
                          &itask->buf,
                          1,
                          NULL,
                          0,
                          (WSAOVERLAPPED *)&itask->ol,
                          NULL) != SOCKET_ERROR ||
                net::last_errno() == WSA_IO_PENDING)
                return true;
        }
        itask->sub_link();

        PUMP_WARN_LOG("net::post_iocp_read_from: WSARecvFrom failed with ec=%d",
                      last_errno());

        return false;
    }
#endif

}  // namespace net
}  // namespace pump