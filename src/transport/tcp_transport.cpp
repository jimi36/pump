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
        pending_send_cnt_(0),
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
        local_address_ = local_address;
        remote_address_ = remote_address;

        // Set channel fd
        poll::channel::__set_fd(fd);
    }

    int32_t tcp_transport::start(
        service *sv, 
        const transport_callbacks &cbs) {
        PUMP_DEBUG_COND_FAIL(
            flow_, 
            return ERROR_INVALID);

        PUMP_DEBUG_COND_FAIL(
            !__set_state(TRANSPORT_INITED, TRANSPORT_STARTING), 
            return ERROR_INVALID);

        PUMP_DEBUG_COND_FAIL(
            sv == nullptr,  
            return ERROR_INVALID);
        __set_service(sv);
        
        PUMP_DEBUG_COND_FAIL(
            !cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb,  
            return ERROR_INVALID);
        cbs_ = cbs;

        if (!__open_transport_flow()) {
            __set_state(TRANSPORT_STARTING, TRANSPORT_ERROR);
            PUMP_ERR_LOG("tcp_transport: start failed for opening flow failed");
            PUMP_ASSERT(false);
            return ERROR_FAULT;
        }

        __set_state(TRANSPORT_STARTING, TRANSPORT_STARTED);

        return ERROR_OK;
    }

    void tcp_transport::stop() {
        while (__is_state(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done, Then
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

    void tcp_transport::force_stop() {
        while (__is_state(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done, Then
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

    int32_t tcp_transport::read_for_once() {
        while (__is_state(TRANSPORT_STARTED)) {
            int32_t err = __async_read(READ_ONCE);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    int32_t tcp_transport::read_for_loop() {
        while (__is_state(TRANSPORT_STARTED)) {
            int32_t err = __async_read(READ_LOOP);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    int32_t tcp_transport::send(
        const block_t *b, 
        int32_t size) {
        if (b == nullptr || size == 0) {
            PUMP_WARN_LOG("tcp_transport: send failed with invalid buffer");
            return ERROR_INVALID;
        }

        int32_t ec = ERROR_OK;

        // Add pending send count.
        pending_send_cnt_.fetch_add(1);
        do {
            if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
                PUMP_WARN_LOG("tcp_transport: send failed for transport not started");
                ec = ERROR_UNSTART;
                break;
            }

            auto iob = toolkit::io_buffer::create();
            if (PUMP_UNLIKELY(iob == nullptr || !iob->append(b, size))) {
                PUMP_WARN_LOG("tcp_transport: send failed for creatng io buffer failed");
                if (iob) {
                    iob->sub_ref();
                }
                ec = ERROR_FAULT;
                break;
            }

            if (!__async_send(iob)) {
                PUMP_WARN_LOG("tcp_transport: send failed for async sending failed");
                ec = ERROR_FAULT;
                break;
            }
        } while(false);
        // Resuce pending send count.
        pending_send_cnt_.fetch_sub(1);

        return ec;
    }

    int32_t tcp_transport::send(toolkit::io_buffer *iob) {
        if (iob == nullptr || iob->data_size() == 0) {
            PUMP_WARN_LOG("tcp_transport: send failed with invalid io buffer");
            return ERROR_INVALID;
        }

        int32_t ec = ERROR_OK;

        // Add pending send count.
        pending_send_cnt_.fetch_add(1);

        if (PUMP_UNLIKELY(!__is_state(TRANSPORT_STARTED))) {
            PUMP_WARN_LOG("tcp_transport: send failed for not started");
            ec = ERROR_UNSTART;
            goto end;
        }

        iob->add_ref();

        if (!__async_send(iob)) {
            PUMP_WARN_LOG("tcp_transport: send failed for async sending failed");
            ec = ERROR_FAULT;
            goto end;
        }
        
    end:
        // Resuce pending send count.
        pending_send_cnt_.fetch_sub(1);

        return ec;
    }

    void tcp_transport::on_read_event() {
        block_t b[MAX_TCP_BUFFER_SIZE];
        int32_t size = flow_->read(b, sizeof(b));
        if (PUMP_LIKELY(size != 0)) {
            // If read state is READ_ONCE, change it to READ_PENDING.
            // If read state is READ_LOOP, last state will be seted to READ_LOOP.
            int32_t last_state = READ_ONCE;
            read_state_.compare_exchange_strong(last_state, READ_PENDING);

            // Read callback
            cbs_.read_cb(b, size);

            // If last read state is READ_ONCE, try to change read state to READ_NONE.
            if (last_state == READ_ONCE) {
                last_state = READ_PENDING;
                if (read_state_.compare_exchange_strong(last_state, READ_NONE)) {
                    return;
                }
            }

            if (!__resume_read_tracker()) {
                PUMP_DEBUG_LOG("tcp_transport: handle channel event failed for resuming read tracker failed");
                __try_doing_disconnected_process();
            }
        } else {
            PUMP_DEBUG_LOG("tcp_transport: handle read event failed flow read failed");
            __try_doing_disconnected_process();
        }
    }

    void tcp_transport::on_send_event() {
        int32_t ret;

        // Continue to send last buffer.
        if (last_send_iob_ != nullptr) {
            ret = flow_->send();
            if (ret == flow::FLOW_ERR_NO) {
                // Reset last sent buffer.
                __reset_last_sent_iobuffer();
                // Reduce pending send size.
                if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
                    goto send_next;
                }
                goto end;   
            } else if (ret == flow::FLOW_ERR_AGAIN) {
                PUMP_DEBUG_CHECK(__resume_send_tracker());
                return;
            } else {
                PUMP_DEBUG_LOG("tcp_transport: handle send event failed for flow send failed");
                __try_doing_disconnected_process();
                return;
            }
        }
 
      send_next :
        // Send next buffer.
        ret = __send_once();
        if (ret == ERROR_OK) {
            goto end;
        } else if (ret == ERROR_AGAIN) {
            PUMP_DEBUG_CHECK(__resume_send_tracker());
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

    bool tcp_transport::__open_transport_flow() {
        // Init tcp transport flow.
        flow_.reset(
            object_create<flow::flow_tcp>(), 
            object_delete<flow::flow_tcp>);
        PUMP_DEBUG_COND_FAIL(
            !flow_, 
            return false);
        if (flow_->init(shared_from_this(), get_fd()) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("tcp_transport: open transport flow failed for flow init failed");
            return false;
        }

        return true;
    }

    int32_t tcp_transport::__async_read(int32_t state) {
        int32_t current_state = __change_read_state(state);
        if (current_state >= READ_PENDING) {
            return ERROR_OK;
        } else if (current_state == READ_INVALID) {
            return ERROR_AGAIN;
        }

        if (!__start_read_tracker()) {
            PUMP_DEBUG_LOG("tcp_transport: async read failed for starting tracker failed");
            return ERROR_FAULT;
        }

        return ERROR_OK;
    }

    bool tcp_transport::__async_send(toolkit::io_buffer *iob) {
        // Push buffer to sendlist.
        PUMP_DEBUG_CHECK(sendlist_.push(iob));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(iob->data_size()) > 0) {
            return true;
        }

        auto ret = __send_once();
        if (PUMP_LIKELY(ret == ERROR_OK)) {
            return true;
        } else if (ret == ERROR_AGAIN) {  
            if (!__start_send_tracker()) {
                PUMP_DEBUG_LOG("tcp_transport: send once failed for starting send tracker failed");
                return false;
            }
            return true;
        }
        
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
            __post_channel_event(shared_from_this(), 0);
        }

        PUMP_DEBUG_LOG("tcp_transport: async send failed for sending once failed");

        return false;
    }

    int32_t tcp_transport::__send_once() {
        PUMP_ASSERT(!last_send_iob_);
        // Pop next buffer from sendlist to send.
        PUMP_DEBUG_CHECK(sendlist_.pop(last_send_iob_));
        // Save last send buffer data size.
        last_send_iob_size_ = last_send_iob_->data_size();

        // Try to send the buffer.
        auto ret = flow_->want_to_send(last_send_iob_);
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

        PUMP_DEBUG_LOG("tcp_transport: send once faled for flow want to send failed");

        return ERROR_FAULT;
    }

    void tcp_transport::__try_doing_disconnected_process() {
        if (__set_state(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
            __interrupt_and_trigger_callbacks();
        }
    }

    void tcp_transport::__clear_sendlist() {
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
