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

#include "pump/transport/tcp_transport.h"

namespace pump {
namespace transport {

    tcp_transport::tcp_transport() noexcept
      : base_transport(TCP_TRANSPORT, nullptr, -1),
        last_send_iob_size_(0),
        last_send_iob_(nullptr),
        pending_opt_cnt_(0),
        sendlist_(32) {
    }

    tcp_transport::~tcp_transport() {
        __stop_read_tracker();
        __stop_send_tracker();
        __clear_sendlist();
    }

    void tcp_transport::init(
        pump_socket fd,
        const address &local_address,
        const address &remote_address) {
        // Set addresses.
        local_address_ = local_address;
        remote_address_ = remote_address;
        // Set channel fd
        poll::channel::__set_fd(fd);
    }

    error_code tcp_transport::start(
        service *sv, 
        read_mode mode,
        const transport_callbacks &cbs) {
        PUMP_DEBUG_FAILED(
            !__set_state(TRANSPORT_INITED, TRANSPORT_STARTING),
            "tcp_transport: start failed for transport state incorrect",
            return ERROR_INVALID);

        bool ret = false;
        toolkit::defer cleanup([&]() {
            if (ret) {
                __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);
            } else {
                __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
                __close_transport_flow();
            }
        });

       PUMP_DEBUG_FAILED(
            !!flow_, 
            "tcp_transport: start failed for flow already exists",
            return ERROR_INVALID);

        PUMP_DEBUG_FAILED(
            sv == nullptr, 
            "tcp_transport: start failed for service invalid",
            return ERROR_INVALID);
        __set_service(sv);

        PUMP_DEBUG_FAILED(
            mode != READ_MODE_ONCE && mode != READ_MODE_LOOP,
            "tcp_transport: start failed for transport state incorrect",
            return ERROR_INVALID);
        rmode_ = mode;
        
        PUMP_DEBUG_FAILED(
            !cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb,
            "tcp_transport: start failed for callbacks invalid",
            return ERROR_INVALID);
        cbs_ = cbs;

        if (!__open_transport_flow()) {
            PUMP_DEBUG_LOG("tcp_transport: start failed for opening flow failed");
            return ERROR_FAULT;
        }

        PUMP_DEBUG_CHECK(__change_read_state(READ_NONE, READ_PENDING));
        if (!__start_read_tracker()) {
            PUMP_WARN_LOG("tcp_transport: start failed for starting tracker failed");
            return ERROR_FAULT;
        }

        ret = true;

        return ERROR_OK;
    }

    void tcp_transport::stop() {
        while (is_started()) {
            // Change state from started to stopping.
            if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                // Wait pending opt count reduce to zero.
                while (pending_opt_cnt_.load(std::memory_order_relaxed) != 0);
                // If no data to send, shutdown transport flow and post channel event,
                // else shutdown transport flow read and wait finishing send.
                if (pending_send_size_.load(std::memory_order_acquire) == 0) {
                    __shutdown_transport_flow(SHUT_RDWR);
                    __post_channel_event(shared_from_this(), 0);
                } else {
                    __shutdown_transport_flow(SHUT_RD);
                }
                return;
            }
        }

        // If in disconnecting state at the moment, it means transport is
        // disconnected but hasn't triggered callback yet. So we just change
        // state to stopping, and then transport will trigger stopped callabck.
        __set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING);
    }

    void tcp_transport::force_stop() {
        while (is_started()) {
            // Change state from started to stopping.
            if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                // Wait pending opt count reduce to zero.
                while (pending_opt_cnt_.load(std::memory_order_relaxed) != 0);
                // Shutdown transport flow.
                __shutdown_transport_flow(SHUT_RDWR);
                // Post channel event.
                __post_channel_event(shared_from_this(), 0);
                return;
            }
        }

        // If in disconnecting state at the moment, it means transport is
        // disconnected but hasn't triggered callback yet. So we just change
        // state to stopping, and then transport will trigger stopped callabck.
        __set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING);
    }

    error_code tcp_transport::read_continue() {
        if (!is_started()) {
            PUMP_DEBUG_LOG("tcp_transport: read continue failed for not in started");
            return ERROR_UNSTART;
        }

        error_code ec = ERROR_OK;
        pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
        do {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_DEBUG_LOG("tcp_transport: read continue failed for not in started");
                ec = ERROR_UNSTART;
                break;
            }
            if (rmode_ != READ_MODE_ONCE ||
                !__change_read_state(READ_NONE, READ_PENDING) || 
                !__resume_read_tracker()) {
                ec = ERROR_FAULT;
            }
        } while (false);
        pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

        return ec;
    }

    error_code tcp_transport::send(
        const block_t *b, 
        int32_t size) {
        PUMP_DEBUG_FAILED(
            b == nullptr || size <= 0, 
            "tcp_transport: send failed for buffer invalid",
            return ERROR_INVALID);

        if (!is_started()) {
            PUMP_DEBUG_LOG("tcp_transport: send failed for not in started");
            return ERROR_UNSTART;
        }

        error_code ec = ERROR_OK;
        pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
        do {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_DEBUG_LOG("tcp_transport: send failed for not in started");
                ec = ERROR_UNSTART;
                break;
            }

            auto iob = toolkit::io_buffer::create();
            if (PUMP_UNLIKELY(iob == nullptr || !iob->append(b, size))) {
                PUMP_WARN_LOG("tcp_transport: send failed for creatng io buffer failed");
                if (iob) {
                    iob->sub_refence();
                }
                ec = ERROR_FAULT;
                break;
            }

            if (!__async_send(iob)) {
                PUMP_DEBUG_LOG("tcp_transport: send failed for async sending failed");
                ec = ERROR_FAULT;
            }
        } while(false);
        pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

        return ec;
    }

    error_code tcp_transport::send(toolkit::io_buffer *iob) {
        PUMP_DEBUG_FAILED(
            iob == nullptr || iob->data_size() == 0, 
            "tcp_transport: send failed for io buffer invalid",
            return ERROR_INVALID);

        if (!is_started()) {
            PUMP_DEBUG_LOG("tcp_transport: send failed for not in started");
            return ERROR_UNSTART;
        }

        error_code ec = ERROR_OK;
        pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
        do
        {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_DEBUG_LOG("tcp_transport: send failed for not in started");
                ec = ERROR_UNSTART;
                break;
            }

            iob->add_refence();
            if (!__async_send(iob)) {
                PUMP_DEBUG_LOG("tcp_transport: send failed for async sending failed");
                ec = ERROR_FAULT;
            }
        } while (false);
        pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

        return ec;
    }

    void tcp_transport::on_read_event() {
        // If transport is starting, resume read tracker.
        if (__is_state(TRANSPORT_STARTING, std::memory_order_relaxed)) {
            PUMP_DEBUG_LOG("tcp_transport: handle read failed for starting");
            if (!__resume_read_tracker()) {
                PUMP_WARN_LOG("tcp_transport: handle read failed for resuming tracker failed");
                __try_triggering_disconnected_callback();
                return;
            }
        }

        block_t data[MAX_TCP_BUFFER_SIZE];
        int32_t size = flow_->read(data, sizeof(data));
        if (PUMP_LIKELY(size != 0)) {
            if (rmode_ == READ_MODE_ONCE) {
                // Change read state from READ_PENDING to READ_NONE.
                if (!__change_read_state(READ_PENDING, READ_NONE)) {
                    PUMP_WARN_LOG("tcp_transport: handle read failed for changing read state");
                    goto disconnected;
                }
            } else {
                // Resume read tracker.
                if (!__resume_read_tracker()) {
                    PUMP_WARN_LOG("tcp_transport: handle read failed for resuming tracker failed");
                    goto disconnected;
                }
            }
            // Callback data.
            cbs_.read_cb(data, size);
            return;
        } else {
            PUMP_DEBUG_LOG("tcp_transport: handle read failed for disconnected");
        }

    disconnected:
        __try_triggering_disconnected_callback();
    }

    void tcp_transport::on_send_event() {
        if (last_send_iob_ != nullptr) {
            switch (flow_->send())
            {
            case ERROR_OK:
                __reset_last_sent_iobuffer();
                if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
                    goto continue_send;
                }
                goto end;
            case ERROR_AGAIN:
                if (!__resume_send_tracker()) {
                    PUMP_WARN_LOG("tcp_transport: handle send failed for resuming tracker failed");
                    goto disconnected;
                }
                return;
            default:
                PUMP_DEBUG_LOG("tcp_transport: handle send failed for sending failed");
                goto disconnected;
            }
        }
 
    continue_send:
        switch (__send_once())
        {
        case ERROR_OK:
            goto end;
        case ERROR_AGAIN:
            if (!__resume_send_tracker()) {
                PUMP_WARN_LOG("tcp_transport: handle send failed for resuming tracker failed");
                goto disconnected;
            }
            return;
        default:
            PUMP_DEBUG_LOG("tcp_transport: handle send failed for sending once failed");
            goto disconnected;
        }

    disconnected:
        if (__try_triggering_disconnected_callback()) {
            return;
        }

    end:
        __trigger_stopped_callback();
    }

    bool tcp_transport::__open_transport_flow() {
        // Init tcp transport flow.
        flow_.reset(
            object_create<flow::flow_tcp>(), 
            object_delete<flow::flow_tcp>);
        if (!flow_) {
            PUMP_WARN_LOG("tcp_transport: open flow failed for creating flow failed");
            return false;
        }
        if (flow_->init(shared_from_this(), get_fd()) != ERROR_OK) {
            PUMP_DEBUG_LOG("tcp_transport: open flow failed for initing flow failed");
            return false;
        }

        return true;
    }

    void tcp_transport::__shutdown_transport_flow(int32_t how) {
        if (flow_) {
            flow_->shutdown(how);
        }
    }

    void tcp_transport::__close_transport_flow() {
        if (flow_) {
            flow_->close();
        }
    }

    bool tcp_transport::__async_send(toolkit::io_buffer *iob) {
        // Push buffer to sendlist.
        PUMP_DEBUG_CHECK(sendlist_.push(iob));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(iob->data_size()) > 0) {
            return true;
        }

        switch (__send_once())
        {
        case ERROR_OK:
            return true;
        case ERROR_AGAIN:
            if (!__start_send_tracker()) {
                PUMP_WARN_LOG("tcp_transport: async send failed for starting tracker failed");
                break;
            }
            return true;
        default:
            PUMP_DEBUG_LOG("tls_transport: async send failed for sending once failed");
            break;
        }

        if (__set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
            __post_channel_event(shared_from_this(), 0);
        }

        return false;
    }

    error_code tcp_transport::__send_once() {
        PUMP_ASSERT(!last_send_iob_);
        // Pop next buffer from sendlist to send.
        PUMP_DEBUG_CHECK(sendlist_.pop(last_send_iob_));
        // Save last send buffer data size.
        last_send_iob_size_ = last_send_iob_->data_size();

        // Try to send the buffer.
        auto ret = flow_->want_to_send(last_send_iob_);
        if (PUMP_LIKELY(ret == ERROR_OK)) {
            // Reset last sent buffer.
            __reset_last_sent_iobuffer();
            // Reduce pending send size.
            if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
                return ERROR_AGAIN;
            }
            return ERROR_OK;
        } else if (ret == ERROR_AGAIN) {
            return ERROR_AGAIN;
        }

        PUMP_DEBUG_LOG("tcp_transport: send once failed for wanting to send failed");

        return ERROR_FAULT;
    }

    void tcp_transport::__clear_sendlist() {
        if (last_send_iob_ != nullptr) {
            last_send_iob_->sub_refence();
        }

        toolkit::io_buffer *iob;
        while (sendlist_.pop(iob)) {
            iob->sub_refence();
        }
    }

}  // namespace transport
}  // namespace pump
