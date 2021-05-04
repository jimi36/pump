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

#include "pump/transport/tls_transport.h"

namespace pump {
namespace transport {

    tls_transport::tls_transport() noexcept
      : base_transport(TLS_TRANSPORT, nullptr, -1),
        last_send_iob_size_(0),
        last_send_iob_(nullptr),
        pending_opt_cnt_(0),
        sendlist_(32) {
    }

    tls_transport::~tls_transport() {
        __stop_read_tracker();
        __stop_send_tracker();
        __clear_send_pockets();
    }

    void tls_transport::init(
        flow::flow_tls_sptr &flow,
        const address &local_address,
        const address &remote_address) {
        local_address_ = local_address;
        remote_address_ = remote_address;

        PUMP_ASSERT(flow);
        flow_ = flow;

        // Set channel fd
        poll::channel::__set_fd(flow->get_fd());
    }

    error_code tls_transport::start(
        service *sv, 
        read_mode mode,
        const transport_callbacks &cbs) {
        PUMP_DEBUG_FAILED(
            !__set_state(TRANSPORT_INITED, TRANSPORT_STARTING), 
            "tls_transport: start failed for transport state incorrect",
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
            !flow_, 
            "tls_transport: start failed for flow invalid",
            return ERROR_INVALID);

        PUMP_DEBUG_FAILED(
            sv == nullptr, 
            "tls_handshaker: start failed for service invalid",
            return ERROR_INVALID);
        __set_service(sv);

        PUMP_DEBUG_FAILED(
            mode != READ_MODE_ONCE && mode != READ_MODE_LOOP,
            "tls_transport: start failed for transport state incorrect",
            return ERROR_INVALID);
        rmode_ = mode;

        PUMP_DEBUG_FAILED(
            !cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb, 
            "tls_handshaker: start failed for callbacks invalid",
            return ERROR_INVALID);
        cbs_ = cbs;

        PUMP_DEBUG_CHECK(__change_read_state(READ_NONE, READ_PENDING));
        if (flow_->has_unread_data()) {
            if (!__post_channel_event(shared_from_this(), 1, READ_POLLER_ID)) {
                PUMP_WARN_LOG("tls_transport: start failed for posting channel event failed");
                return ERROR_FAULT;
            }
        } else if (!__start_read_tracker()) {
            PUMP_WARN_LOG("tls_transport: start failed for starting tracker failed");
            return ERROR_FAULT;
        }

        ret = true;

        return ERROR_OK;
    }

    void tls_transport::stop() {
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

    void tls_transport::force_stop() {
        while (is_started()) {
            // Change state from started to stopping.
            if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                // Wait pending opt count reduce to zero.
                while (pending_opt_cnt_.load(std::memory_order_relaxed) != 0);
                // Shutdown transport flow and post channel event.
                __shutdown_transport_flow(SHUT_RDWR);
                __post_channel_event(shared_from_this(), 0);
                return;
            }
        }

        // If in disconnecting state at the moment, it means transport is
        // disconnected but hasn't triggered callback yet. So we just change
        // state to stopping, and then transport will trigger stopped callabck.
        __set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING);
    }

    error_code tls_transport::read_continue() {
        if (!is_started()) {
            PUMP_DEBUG_LOG("tls_transport: read continue failed for not in started");
            return ERROR_UNSTART;
        }

        error_code ec = ERROR_OK;
        pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
        do {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_DEBUG_LOG("tls_transport: read continue failed for not in started");
                ec = ERROR_UNSTART;
                break;
            }
            if (rmode_ != READ_MODE_ONCE ||
                !__change_read_state(READ_NONE, READ_PENDING)) {
                ec = ERROR_FAULT;
                break;
            }
            if (flow_->has_unread_data()) {
                __post_channel_event(shared_from_this(), 1, READ_POLLER_ID);
            } else if (!__start_read_tracker()) {
                PUMP_WARN_LOG("tls_transport: async read failed for starting tracker failed");
                ec = ERROR_FAULT;
            }
        } while (false);
        pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

        return ec;
    }

    error_code tls_transport::send(
        const block_t *b, 
        int32_t size) {
        PUMP_DEBUG_FAILED(
            b == nullptr || size <= 0, 
            "tls_transport: send failed for buffer invalid",
            return ERROR_INVALID);

        if (!is_started()) {
            PUMP_DEBUG_LOG("tls_transport: send failed for not in started");
            return ERROR_UNSTART;
        }

        error_code ec = ERROR_OK;
        pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
        do
        {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_DEBUG_LOG("tls_transport: send failed for not in started");
                ec = ERROR_UNSTART;
                break;
            }

            auto *iob = toolkit::io_buffer::create();
            if (PUMP_UNLIKELY(iob == nullptr || !iob->append(b, size))) {
                PUMP_WARN_LOG("tls_transport: send failed for creating io buffer failed");
                if (iob != nullptr) {
                    iob->sub_refence();
                }
                ec = ERROR_AGAIN;
                break;
            }

            if (!__async_send(iob)) {
                PUMP_DEBUG_LOG("tls_transport: send failed for async sending failed");
                ec = ERROR_FAULT;
            }
        } while (false);
        pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

        return ec;
    }

    error_code tls_transport::send(toolkit::io_buffer *iob) {
        PUMP_DEBUG_FAILED(
            iob == nullptr || iob->data_size() == 0, 
            "tls_transport: send failed for io buffer invalid",
            return ERROR_INVALID);

        if (!is_started()) {
            PUMP_DEBUG_LOG("tls_transport: send failed for not in started");
            return ERROR_UNSTART;
        }

        error_code ec = ERROR_OK;
        pending_opt_cnt_.fetch_add(1, std::memory_order_relaxed);
        do
        {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_DEBUG_LOG("tls_transport: send failed for not in started");
                ec = ERROR_UNSTART;
                break;
            }

            iob->add_refence();
            if (!__async_send(iob)) {
                PUMP_DEBUG_LOG("tls_transport: send failed for async sending failed");
                ec = ERROR_FAULT;
            }
        } while (false);
        pending_opt_cnt_.fetch_sub(1, std::memory_order_relaxed);

        return ec;
    }

    void tls_transport::on_channel_event(int32_t ev) {
        if (ev == 0) {
            base_transport::on_channel_event(ev);
            return;
        }

        PUMP_ASSERT(ev = 1);
        if (__is_state(TRANSPORT_STARTING, std::memory_order_relaxed)) {
            PUMP_DEBUG_LOG("tls_transport: handle channel event failed for starting");
            if (!__post_channel_event(shared_from_this(), 1, READ_POLLER_ID)) {
                PUMP_WARN_LOG("tcp_transport: handle channel event failed for posting channel event failed");
                __try_triggering_disconnected_callback();
                return;
            }
        }

        block_t data[MAX_TCP_BUFFER_SIZE];
        int32_t size = flow_->read(data, sizeof(data));
        if (PUMP_LIKELY(size > 0)) {
            if (rmode_ == READ_MODE_ONCE) {
                // Change read state from READ_PENDING to READ_NONE.
                if (!__change_read_state(READ_PENDING, READ_NONE)) {
                    PUMP_WARN_LOG("tls_transport: handle channel event failed for changing read state");
                    goto disconnected;
                }
            } else {
                // Start read tracker.
                if (!__start_read_tracker()) {
                    PUMP_WARN_LOG("tls_transport: handle channel event failed for starting tracker failed");
                    goto disconnected;
                }
            }
            // Callback read data.
            cbs_.read_cb(data, size);
            return;
        } else if (size < 0) {
            if (!__resume_read_tracker()) {
                PUMP_WARN_LOG("tls_transport: handle channel failed for starting tracker failed");
                goto disconnected;
            }
            return;
        } else {
            PUMP_DEBUG_LOG("tls_transport: handle channel failed for reading from ssl failed");
        }

    disconnected:
        __try_triggering_disconnected_callback();
    }

    void tls_transport::on_read_event() {
        // If transport is in starting, resume read tracker.
        if (__is_state(TRANSPORT_STARTING, std::memory_order_relaxed)) {
            PUMP_DEBUG_LOG("tls_transport: handle read failed for starting");
            if (!__resume_read_tracker()) {
                PUMP_WARN_LOG("tls_transport: handle read failed for resuming tracker failed");
                __try_triggering_disconnected_callback();
                return;
            }
        }

        block_t data[MAX_TCP_BUFFER_SIZE];
        int32_t size = flow_->read(data, sizeof(data));
        if (PUMP_LIKELY(size > 0)) {
            if (rmode_ == READ_MODE_ONCE) {
                // Change read state from READ_PENDING to READ_NONE.
                if (!__change_read_state(READ_PENDING, READ_NONE)) {
                    PUMP_WARN_LOG("tls_transport: handle read failed for changing read state");
                    goto disconnected;
                }
            } else {
                // Resume read tracker.
                if (!__resume_read_tracker()) {
                    PUMP_WARN_LOG("tls_transport: handle read failed for starting tracker failed");
                    goto disconnected;
                }
            }
            // Callback data.
            cbs_.read_cb(data, size);
            return;
        } else if (size < 0) {
            if (!__resume_read_tracker()) {
                PUMP_WARN_LOG("tls_transport: handle read failed for starting tracker failed");
                goto disconnected;
            }
            return;
        } else {
            PUMP_DEBUG_LOG("tls_transport: handle read failed for disconnected");
        }

    disconnected:
        __try_triggering_disconnected_callback();
    }

    void tls_transport::on_send_event() {
        if (PUMP_LIKELY(last_send_iob_ != nullptr)) {
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
                    PUMP_WARN_LOG("tls_transport: handle send failed for resuming tracker failed");
                    goto disconnected;
                }
                return;
            default:
                PUMP_DEBUG_LOG("tls_transport: handle send failed for sending failed");
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
                PUMP_WARN_LOG("tls_transport: handle send failed for resuming tracker failed");
                goto disconnected;
            }
            return;
        default:
            PUMP_DEBUG_LOG("tls_transport: handle send failed for sending once failed");
            goto disconnected;
        }

    disconnected:
        if (__try_triggering_disconnected_callback()) {
            return;
        }

    end:
        __trigger_stopped_callback();
    }

    void tls_transport::__shutdown_transport_flow(int32_t how) {
        if (flow_) {
            flow_->shutdown(how);
        }
    }

    void tls_transport::__close_transport_flow() {
        if (flow_) {
            flow_->close();
        }
    }

    bool tls_transport::__async_send(toolkit::io_buffer *iob) {
        // Insert buffer to sendlist.
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
                PUMP_WARN_LOG("tls_transport: async send failed for starting tracker failed");
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

    int32_t tls_transport::__send_once() {
        PUMP_ASSERT(!last_send_iob_);
        // Pop next buffer from sendlist.
        PUMP_DEBUG_CHECK(sendlist_.pop(last_send_iob_));
        // Save last send buffer data size.
        last_send_iob_size_ = last_send_iob_->data_size();

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

        PUMP_DEBUG_LOG("tls_transport: send once failed for wanting to send failed");

        return ERROR_FAULT;
    }

    void tls_transport::__clear_send_pockets() {
        if (last_send_iob_) {
            last_send_iob_->sub_refence();
        }

        toolkit::io_buffer *iob;
        while (sendlist_.pop(iob)) {
            iob->sub_refence();
        }
    }

}  // namespace transport
}  // namespace pump
