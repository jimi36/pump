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

#ifndef pump_net_iocp_h
#define pump_net_iocp_h

#include "pump/config.h"
#include "pump/net/iocp_extra.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace net {

#if defined(PUMP_HAVE_IOCP)

    const int32 IOCP_READ_MASKS = 0x10;
    const int32 IOCP_SEND_MASKS = 0x20;

    const int32 IOCP_TASK_NONE = 0x00;
    const int32 IOCP_TASK_READ = IOCP_READ_MASKS;
    const int32 IOCP_TASK_ACCEPT = IOCP_READ_MASKS | 0x01;
    const int32 IOCP_TASK_SEND = IOCP_SEND_MASKS;
    const int32 IOCP_TASK_CONNECT = IOCP_SEND_MASKS | 0x01;
    const int32 IOCP_TASK_CHANNEL = 0x40;

    typedef void_ptr iocp_handler;

    struct iocp_task {
        // IOCP overlapped
        WSAOVERLAPPED ol;
        // IOCP buffer
        WSABUF buf_;
        // IOCP task type
        int32 type_;
        // IOCP processed size
        DWORD processed_size_;
        // IOCP fd
        int32 fd_;
        // IOCP error code
        int32 errcode_;
        // Channel notifier
        std::weak_ptr<void> ch_notifier_;
        // IO buffer
        toolkit::io_buffer_ptr iob_;
        // Ref link count
        std::atomic_int link_cnt_;

        union {
            // Client fd for accepting
            int32 client_fd;
            // IP address for connecting
            struct {
                int8 addr[64];
                int32 addr_len;
            } ip;
        } un_;

        iocp_task() noexcept
            : type_(IOCP_TASK_NONE),
              processed_size_(0),
              fd_(-1),
              errcode_(0),
              iob_(nullptr),
              link_cnt_(1) {
            memset(&ol, 0, sizeof(ol));
            memset(&un_, 0, sizeof(un_));
        }

        /*********************************************************************************
         * Add link count
         ********************************************************************************/
        PUMP_INLINE void add_link() {
            link_cnt_.fetch_add(1);
        }

        /*********************************************************************************
         * Sub link count
         ********************************************************************************/
        PUMP_INLINE void sub_link() {
            if (link_cnt_.fetch_sub(1) == 1) {
                __release_resource();
                object_delete(this);
            }
        }

        /*********************************************************************************
         * Reuse task
         * This will reset iocp overlapped.
         ********************************************************************************/
        PUMP_INLINE void reuse() {
            memset(&ol, 0, sizeof(ol));
        }

        /*********************************************************************************
         * Set task type
         ********************************************************************************/
        PUMP_INLINE void set_type(int32 tp) {
            type_ = tp;
        }

        /*********************************************************************************
         * Get task type
         ********************************************************************************/
        PUMP_INLINE int32 get_type() {
            return type_;
        }

        /*********************************************************************************
         * Set task fd
         ********************************************************************************/
        PUMP_INLINE void set_fd(int32 fd) {
            fd_ = fd;
        }

        /*********************************************************************************
         * Get task fd
         ********************************************************************************/
        PUMP_INLINE int32 get_fd(void_ptr task) {
            return fd_;
        }

        /*********************************************************************************
         * Set client socket fd
         ********************************************************************************/
        PUMP_INLINE void set_client_fd(int32 client_fd) {
            un_.client_fd = client_fd;
        }

        /*********************************************************************************
         * Get client socket fd
         ********************************************************************************/
        PUMP_INLINE int32 get_client_fd() {
            return un_.client_fd;
        }

        /*********************************************************************************
         * Set task notifier
         ********************************************************************************/
        PUMP_INLINE void set_notifier(void_wptr ch) {
            PUMP_ASSERT(ch.lock());
            ch_notifier_ = ch;
        }

        /*********************************************************************************
         * Get iocp task notify
         ********************************************************************************/
        PUMP_INLINE void_sptr get_notifier() {
            return ch_notifier_.lock();
        }

        /*********************************************************************************
         * Set error code
         ********************************************************************************/
        PUMP_INLINE void set_errcode(int32 ec) {
            errcode_ = ec;
        }

        /*********************************************************************************
         * Get error code
         ********************************************************************************/
        PUMP_INLINE int32 get_errcode() {
            return errcode_;
        }

        /*********************************************************************************
         * Bind io buffer
         * If iob has data, task will use iob data size binding.
         * If iob has no data, task vill use iob buffer size binding.
         ********************************************************************************/
        PUMP_INLINE void bind_io_buffer(toolkit::io_buffer_ptr iob) {
            iob->add_ref();
            iob_ = iob;
            if (iob->data_size() > 0) {
                buf_.buf = (block_ptr)iob->data();
                buf_.len = iob->data_size();
            } else {
                buf_.buf = (block_ptr)iob->buffer();
                buf_.len = iob->buffer_size();
            }
        }

        /*********************************************************************************
         * Unbind io buffer
         ********************************************************************************/
        PUMP_INLINE void unbind_io_buffer() {
            PUMP_ASSERT(iob_);
            iob_->sub_ref();
        }

        /*********************************************************************************
         * Update io buffer
         * Task vill use iob data info update.
         ********************************************************************************/
        PUMP_INLINE void update_io_buffer() {
            PUMP_ASSERT(iob_);
            buf_.len = iob_->data_size();
            buf_.buf = (block_ptr)iob_->data();
        }

        /*********************************************************************************
         * Set processed size
         ********************************************************************************/
        PUMP_INLINE void set_processed_size(int32 size) {
            processed_size_ = size;
        }

        /*********************************************************************************
         * Get processed size
         ********************************************************************************/
        PUMP_INLINE int32 get_processed_size() {
            return processed_size_;
        }

        /*********************************************************************************
         * Get processed data
         ********************************************************************************/
        PUMP_INLINE block_ptr get_processed_data(int32_ptr size) {
            *size = processed_size_;
            return buf_.buf;
        }

        /*********************************************************************************
         * Get remote address for udp reading from
         ********************************************************************************/
        PUMP_INLINE sockaddr *get_remote_address(int32_ptr addrlen) {
            *addrlen = un_.ip.addr_len;
            return (sockaddr *)un_.ip.addr;
        }

        /*********************************************************************************
         * Release resource
         ********************************************************************************/
        PUMP_INLINE void __release_resource() {
            if (type_ == IOCP_TASK_ACCEPT) {
                if (un_.client_fd > 0) {
                    close(un_.client_fd);
                }
            }
            if (iob_) {
                iob_->sub_ref();
            }
        }
    };
    DEFINE_RAW_POINTER_TYPE(iocp_task);

    /*********************************************************************************
     * Get iocp handler
     ********************************************************************************/
    iocp_handler get_iocp_handler();

    /*********************************************************************************
     * Create an iocp task with a link
     ********************************************************************************/
    PUMP_INLINE iocp_task_ptr new_iocp_task() {
        return object_create<iocp_task>();
    }

    /*********************************************************************************
     * Create iocp socket
     ********************************************************************************/
    int32 create_iocp_socket(int32 domain, int32 type, iocp_handler iocp);

    /*********************************************************************************
     * Post iocp accept
     ********************************************************************************/
    bool post_iocp_accept(void_ptr ex_fns, iocp_task_ptr task);

    /*********************************************************************************
     * Get iocp client address
     ********************************************************************************/
    bool get_iocp_client_address(void_ptr ex_fns,
                                 iocp_task_ptr task,
                                 sockaddr **local,
                                 int32_ptr llen,
                                 sockaddr **remote,
                                 int32_ptr rlen);

    /*********************************************************************************
     * Post iocp connect
     ********************************************************************************/
    bool post_iocp_connect(void_ptr ex_fns,
                           iocp_task_ptr task,
                           const sockaddr *addr,
                           int32 addrlen);

    /*********************************************************************************
     * Post iocp read
     ********************************************************************************/
    bool post_iocp_read(iocp_task_ptr task);

    /*********************************************************************************
     * Post iocp read from
     ********************************************************************************/
    bool post_iocp_read_from(iocp_task_ptr task);

    /*********************************************************************************
     * Post iocp send
     ********************************************************************************/
    bool post_iocp_send(iocp_task_ptr task);

#endif

}  // namespace net
}  // namespace pump

#endif