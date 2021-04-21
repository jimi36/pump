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
        pending_send_cnt_(0),
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

    int32_t tls_transport::start(
        service *sv, 
        const transport_callbacks &cbs) {
        PUMP_DEBUG_FAILED_RUN(
            !flow_, 
            "tls_transport: start failed for flow invalid",
            return ERROR_INVALID);

        PUMP_DEBUG_FAILED_RUN(
            !__set_state(TRANSPORT_INITED, TRANSPORT_STARTING), 
            "tls_transport: start failed for transport state incorrect",
            return ERROR_INVALID);

        PUMP_DEBUG_FAILED_RUN(
            sv == nullptr, 
            "tls_handshaker: start failed for service invalid",
            return ERROR_INVALID);
        __set_service(sv);

        PUMP_DEBUG_FAILED_RUN(
            !cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb, 
            "tls_handshaker: start failed for callbacks invalid",
            return ERROR_INVALID);
        cbs_ = cbs;

        __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);

        return ERROR_OK;
    }

    void tls_transport::stop() {
        while (__is_state(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done. Then
            // tracker event callback will be triggered, we can trigger stopped
            // callabck at there.
            if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                // Wait pending send count reduce to zero.
                while (pending_send_cnt_.load(std::memory_order_relaxed) != 0);
                // Shutdown transport flow.
                __shutdown_transport_flow();
                // If there is data to send, waiting sending finished.
                if (pending_send_size_.load(std::memory_order_acquire) == 0) {
                    __post_channel_event(shared_from_this(), 0);
                }
                return;
            }
        }

        // If in disconnecting status at the moment, it means transport is
        // disconnected but hasn't triggered tracker event callback yet. So we just
        // set stopping status to transport, and when tracker event callback
        // triggered, we will trigger stopped callabck at there.
        if (__set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING)) {
            return;
        }
    }

    void tls_transport::force_stop() {
        while (__is_state(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done. Then
            // tracker event callback will be triggered, we can trigger stopped
            // callabck at there.
            if (__set_state(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                __close_transport_flow();
                __post_channel_event(shared_from_this(), 0);
                return;
            }
        }

        // If in disconnecting status at the moment, it means transport is
        // disconnected but hasn't triggered tracker event callback yet. So we just
        // set stopping status to transport, and when tracker event callback
        // triggered, we will trigger stopped callabck at there.
        if (__set_state(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING)) {
            return;
        }
    }

    int32_t tls_transport::read_for_once() {
        while (__is_state(TRANSPORT_STARTED)) {
            int32_t err = __async_read(READ_ONCE);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    int32_t tls_transport::read_for_loop() {
        while (__is_state(TRANSPORT_STARTED)) {
            int32_t err = __async_read(READ_LOOP);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    int32_t tls_transport::send(
        const block_t *b, 
        int32_t size) {
        PUMP_DEBUG_FAILED_RUN(
            b == nullptr || size <= 0, 
            "tls_transport: send failed for buffer invalid",
            return ERROR_INVALID);

        int32_t ec = ERROR_OK;
        // Add pending send count.
        pending_send_cnt_.fetch_add(1);
        do
        {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_DEBUG_LOG("tls_transport: send failed for not in started");
                ec = ERROR_UNSTART;
                break;
            }

            auto *iob = toolkit::io_buffer::create();
            if (PUMP_UNLIKELY(!iob || !iob->append(b, size))) {
                PUMP_WARN_LOG("tls_transport: send failed for creating io buffer failed");
                if (iob != nullptr) {
                    iob->sub_ref();
                }
                ec = ERROR_AGAIN;
                break;
            }

            if (!__async_send(iob)) {
                PUMP_DEBUG_LOG("tls_transport: send failed for async sending failed");
                ec = ERROR_FAULT;
                break;
            }
        } while (false);
        // Resuce pending send count.
        pending_send_cnt_.fetch_sub(1);

        return ec;
    }

    int32_t tls_transport::send(toolkit::io_buffer *iob) {
        PUMP_DEBUG_FAILED_RUN(
            iob == nullptr && iob->data_size() == 0, 
            "tls_transport: send failed for io buffer invalid",
            return ERROR_INVALID);

        int32_t ec = ERROR_OK;
        // Add pending send count.
        pending_send_cnt_.fetch_add(1);
        do
        {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_DEBUG_LOG("tls_transport: send failed for not in started");
                ec = ERROR_UNSTART;
                break;
            }

            iob->add_ref();
            if (!__async_send(iob)) {
                PUMP_DEBUG_LOG("tls_transport: send failed for async sending failed");
                ec = ERROR_FAULT;
                break;
            }
        } while (false);
        // Resuce pending send count.
        pending_send_cnt_.fetch_sub(1);

        return ec;
    }

    void tls_transport::on_channel_event(int32_t ev) {
        // Check transport started state.
        if (!__is_state(TRANSPORT_STARTED)) {
            __interrupt_and_trigger_callbacks();
            return;
        }

        block_t data[MAX_TCP_BUFFER_SIZE];
        int32_t size = flow_->read(data, sizeof(data));
        if (PUMP_LIKELY(size != 0)) {
            // If read state is READ_ONCE, change it to READ_PENDING.
            // If read state is READ_LOOP, last state will be seted to READ_LOOP.
            int32_t last_state = READ_ONCE;
            read_state_.compare_exchange_strong(last_state, READ_PENDING);

            cbs_.read_cb(data, size);

            // If last read state is READ_ONCE, try to change read state to READ_NONE.
            if (last_state == READ_ONCE) {
                last_state = READ_PENDING;
                if (read_state_.compare_exchange_strong(last_state, READ_NONE)) {
                    return;
                }
            }
        } else if (size == 0) {
            PUMP_DEBUG_LOG("tls_transport: handle channel event failed for reading from ssl failed");
            __try_doing_disconnected_process();
            return;
        }

        if (!__start_read_tracker()) {
            PUMP_WARN_LOG("tls_transport: handle channel event failed for starting tracker failed");
            __try_doing_disconnected_process();
        }
    }

    void tls_transport::on_read_event() {
        block_t data[MAX_TCP_BUFFER_SIZE];
        int32_t size = flow_->read(data, sizeof(data));
        if (PUMP_LIKELY(size > 0)) {
            // If read state is READ_ONCE, change it to READ_PENDING.
            // If read state is READ_LOOP, last state will be seted to READ_LOOP.
            int32_t last_state = READ_ONCE;
            read_state_.compare_exchange_strong(last_state, READ_PENDING);

            cbs_.read_cb(data, size);

            // If last read state is READ_ONCE, try to change read state to READ_NONE.
            if (last_state == READ_ONCE) {
                last_state = READ_PENDING;
                if (read_state_.compare_exchange_strong(last_state, READ_NONE)) {
                    return;
                }
            }
        } else if (size == 0) {
            PUMP_DEBUG_LOG("tls_transport: handle read event failed for reading from ssl failed");
            __try_doing_disconnected_process();
            return;
        }

        if (!__resume_read_tracker()) {
            PUMP_WARN_LOG("tcp_transport: handle read event failed for resuming tracker failed");
            __try_doing_disconnected_process();
        }
    }

    void tls_transport::on_send_event() {
        int32_t ret;

        auto flow = flow_.get();

        // Continue to send last buffer.
        if (PUMP_LIKELY(last_send_iob_ != nullptr)) {
            ret = flow->send();
            if (ret == flow::FLOW_ERR_NO) {
                // Reset last sent buffer.
                __reset_last_sent_iobuffer();
                // Reduce pending send size.
                if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
                    goto send_next;
                }
                goto end;
            } else if (ret == flow::FLOW_ERR_AGAIN) {
                if (!__resume_send_tracker()) {
                    PUMP_DEBUG_LOG("tcp_transport: handle send event failed for resuming tracker failed");
                    __try_doing_disconnected_process();
                }
                return;
            } else {
                PUMP_DEBUG_LOG("tls_transport: handle send event failed for flow send failed");
                __try_doing_disconnected_process();
                return;
            }
        }

      send_next :
        // Send next buffer.
        ret = __send_once(flow);
        if (ret == ERROR_OK) {
            goto end;
        } else if (ret == ERROR_AGAIN) {
            if (!__resume_send_tracker()) {
                PUMP_DEBUG_LOG("tcp_transport: handle send event failed for resuming tracker failed");
                __try_doing_disconnected_process();
            }
            return;
        } else {
            PUMP_DEBUG_LOG("tcp_transport: handle send event failed for sending once failed");
            __try_doing_disconnected_process();
            return;
        }

      end:
        if (__is_state(TRANSPORT_STOPPING)) {
            __interrupt_and_trigger_callbacks();
        }
    }

    int32_t tls_transport::__async_read(int32_t state) {
        int32_t current_state = __change_read_state(state);
        if (current_state >= READ_PENDING) {
            return ERROR_OK;
        } else if (current_state == READ_INVALID) {
            return ERROR_AGAIN;
        }

        if (flow_->has_unread_data()) {
            __post_channel_event(shared_from_this(), 0);
            return ERROR_OK;
        }

        if (!__start_read_tracker()) {
            PUMP_WARN_LOG("tls_transport: async read failed for starting tracker failed");
            return ERROR_FAULT;
        }

        return ERROR_OK;
    }

    bool tls_transport::__async_send(toolkit::io_buffer *iob) {
        // Insert buffer to sendlist.
        PUMP_DEBUG_CHECK(sendlist_.push(iob));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(iob->data_size()) > 0) {
            return true;
        }

        auto ret = __send_once(flow_.get());
        if (ret == ERROR_OK) {
            return true;
        } else if (ret == ERROR_AGAIN) {
            if (!__start_send_tracker()) {
                PUMP_WARN_LOG("tls_transport: async send failed for starting tracker failed");
                return false;
            }
            return true;
        }
        
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
            __post_channel_event(shared_from_this(), 0);
        }

        PUMP_DEBUG_LOG("tls_transport: async send failed for sending once failed");

        return false;
    }

    int32_t tls_transport::__send_once(flow::flow_tls *flow) {
        PUMP_ASSERT(!last_send_iob_);
        // Pop next buffer from sendlist.
        PUMP_DEBUG_CHECK(sendlist_.pop(last_send_iob_));
        // Save last send buffer data size.
        last_send_iob_size_ = last_send_iob_->data_size();

        auto ret = flow->want_to_send(last_send_iob_);
        if (PUMP_LIKELY(ret == flow::FLOW_ERR_NO)) {
            // Reset last sent buffer.
            __reset_last_sent_iobuffer();
            // Reduce pending send size.
            if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
                return ERROR_AGAIN;
            }
            return ERROR_OK;
        } else if (ret == flow::FLOW_ERR_AGAIN) {
            return ERROR_AGAIN;
        }

        PUMP_DEBUG_LOG("tls_transport: send once failed for wanting to send failed");

        return ERROR_FAULT;
    }

    void tls_transport::__try_doing_disconnected_process() {
        // Change transport state from TRANSPORT_STARTED to TRANSPORT_DISCONNECTING.
        __set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING);
        // Interrupt tranport
        __interrupt_and_trigger_callbacks();
    }

    void tls_transport::__clear_send_pockets() {
        if (last_send_iob_) {
            last_send_iob_->sub_ref();
        }

        toolkit::io_buffer *iob;
        while (sendlist_.pop(iob)) {
            iob->sub_ref();
        }
    }

}  // namespace transport
}  // namespace pump
