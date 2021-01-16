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
        __clear_send_pockets();
    }

    void tls_transport::init(flow::flow_tls_sptr &flow,
                             const address &local_address,
                             const address &remote_address) {
        local_address_ = local_address;
        remote_address_ = remote_address;

        PUMP_DEBUG_ASSIGN(flow, flow_, flow);

        // Flow rebind channel
        poll::channel_sptr ch = shared_from_this();
        flow_->rebind_channel(ch);

        // Set channel fd
        poll::channel::__set_fd(flow->get_fd());
    }

    int32_t tls_transport::start(service_ptr sv, const transport_callbacks &cbs) {
        if (!flow_) {
            PUMP_ERR_LOG("tls_transport: start failed with invalid flow");
            return ERROR_INVALID;
        }

        if (!sv) {
            PUMP_ERR_LOG("tls_transport: start failed with invalid service");
            return ERROR_INVALID;
        }

        if (!cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("tls_transport: start failed with invalid callbacks");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("tls_transport: start failed with wrong status");
            return ERROR_INVALID;
        }

        // Set callbacks
        cbs_ = cbs;

        // Set service
        __set_service(sv);

        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        return ERROR_OK;
    }

    void tls_transport::stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done. Then
            // tracker event callback will be triggered, we can trigger stopped
            // callabck at there.
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
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
        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING)) {
            return;
        }
    }

    void tls_transport::force_stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done. Then
            // tracker event callback will be triggered, we can trigger stopped
            // callabck at there.
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                __close_transport_flow();
                __post_channel_event(shared_from_this(), 0);
                return;
            }
        }

        // If in disconnecting status at the moment, it means transport is
        // disconnected but hasn't triggered tracker event callback yet. So we just
        // set stopping status to transport, and when tracker event callback
        // triggered, we will trigger stopped callabck at there.
        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING)) {
            return;
        }
    }

    int32_t tls_transport::read_for_once() {
        while (__is_status(TRANSPORT_STARTED)) {
            int32_t err = __async_read(READ_ONCE);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    int32_t tls_transport::read_for_loop() {
        while (__is_status(TRANSPORT_STARTED)) {
            int32_t err = __async_read(READ_LOOP);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    int32_t tls_transport::send(const block_t *b, int32_t size) {
        if (!b || size == 0) {
            PUMP_ERR_LOG("tls_transport: send failed with invalid buffer");
            return ERROR_INVALID;
        }

        int32_t ec = ERROR_OK;
        toolkit::io_buffer *iob = nullptr;

        // Add pending send count.
        pending_send_cnt_.fetch_add(1);

        if (PUMP_UNLIKELY(!__is_status(TRANSPORT_STARTED))) {
            PUMP_ERR_LOG("tls_transport: send failed for transport not started");
            ec = ERROR_UNSTART;
            goto end;
        }

        iob = toolkit::io_buffer::create();
        if (PUMP_UNLIKELY(!iob || !iob->append(b, size))) {
            PUMP_WARN_LOG("tls_transport: send failed for creating io buffer failed");
            if (!iob) {
                iob->sub_ref();
            }
            ec = ERROR_AGAIN;
            goto end;
        }

        if (!__async_send(iob)) {
            PUMP_WARN_LOG("tls_transport: send failed for async sending failed");
            ec = ERROR_FAULT;
            goto end;
        }

    end:
        // Resuce pending send count.
        pending_send_cnt_.fetch_sub(1);

        return ec;
    }

    int32_t tls_transport::send(toolkit::io_buffer_ptr iob) {
        if (!iob || iob->data_size() == 0) {
            PUMP_ERR_LOG("tls_transport: send failed with invalid io buffer");
            return ERROR_INVALID;
        }

        int32_t ec = ERROR_OK;

        // Add pending send count.
        pending_send_cnt_.fetch_add(1);

        if (PUMP_UNLIKELY(!__is_status(TRANSPORT_STARTED))) {
            PUMP_ERR_LOG("tls_transport: send failed for transport no started");
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

    void tls_transport::on_channel_event(int32_t ev) {
        if (!__is_status(TRANSPORT_STARTED)) {
            __interrupt_and_trigger_callbacks();
            return;
        }

        auto flow = flow_.get();

        if (!flow->has_data_to_read()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->post_read() == flow::FLOW_ERR_ABORT) {
                PUMP_WARN_LOG("tls_transport: handle channel event failed for flow post read task failed");
                __try_doing_disconnected_process();
            }
#else
            if (!__start_read_tracker(shared_from_this())) {
                PUMP_WARN_LOG("tls_transport: handle channel event failed for starting read tracker failed");
                __try_doing_disconnected_process();
            }
#endif
            return;
        }

        int32_t size = 0;
        block_t data[MAX_TCP_BUFFER_SIZE];
        int32_t last_state = (uint32_t)READ_NONE;

    read_loop:
        size = flow->read_from_ssl(data, MAX_TCP_BUFFER_SIZE);
        if (PUMP_UNLIKELY(size == 0)) {
            PUMP_WARN_LOG("tls_transport: handle channel event  failed for reading from ssl failed");
            __try_doing_disconnected_process();
            return;
        }

        // Read callback
        if (PUMP_LIKELY(size > 0)) {
            // If read state is READ_ONCE, change it to READ_PENDING.
            // If read state is READ_LOOP, last state will be seted to READ_LOOP.
            last_state = READ_ONCE;
            read_state_.compare_exchange_strong(last_state, READ_PENDING);

            cbs_.read_cb(data, size);

            // If last read state is READ_ONCE, try to change read state to READ_NONE.
            if (last_state == READ_ONCE) {
                last_state = READ_PENDING;
                if (read_state_.compare_exchange_strong(last_state, READ_NONE)) {
                    return;
                }
            }

            goto read_loop;
        }

        // If transport is not in started state, try to interrupt the transport.
        if (!__is_status(TRANSPORT_STARTED)) {
            if (pending_send_size_.load(std::memory_order_acquire) <= 0) {
                __interrupt_and_trigger_callbacks();
            }
            return;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->post_read() == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("tls_transport: handle channel event failed for flow post read task failed");
            __try_doing_disconnected_process();
        }
#else
        if (!__start_read_tracker(shared_from_this())) {
            PUMP_WARN_LOG("tls_transport: handle channel event failed for starting read tracker failed");
            __try_doing_disconnected_process();
        }
#endif
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_transport::on_read_event(net::iocp_task_ptr iocp_task) {
#else
    void tls_transport::on_read_event() {
#endif
        auto flow = flow_.get();

#if defined(PUMP_HAVE_IOCP)
        if (PUMP_UNLIKELY(flow->read_from_net(iocp_task) == flow::FLOW_ERR_ABORT)) {
#else
        if (PUMP_UNLIKELY(flow->read_from_net() == flow::FLOW_ERR_ABORT)) {
#endif
            PUMP_WARN_LOG("tls_transport: handle read event failed for flow read from net failed");
            __try_doing_disconnected_process();
            return;
        }

        int32_t size = 0;
        block_t data[MAX_TCP_BUFFER_SIZE];
        int32_t last_state = (uint32_t)READ_NONE;

    read_loop:
        size = flow->read_from_ssl(data, MAX_TCP_BUFFER_SIZE);
        if (PUMP_UNLIKELY(size == 0)) {
            PUMP_WARN_LOG("tls_transport: handle read event failed for flow read from ssl failed");
            __try_doing_disconnected_process();
            return;
        }

        if (PUMP_LIKELY(size > 0)) {
            // If read state is READ_ONCE, change it to READ_PENDING.
            // If read state is READ_LOOP, last state will be seted to READ_LOOP.
            last_state = READ_ONCE;
            read_state_.compare_exchange_strong(last_state, READ_PENDING);

            cbs_.read_cb(data, size);

            // If last read state is READ_ONCE, try to change read state to READ_NONE.
            if (last_state == READ_ONCE) {
                last_state = READ_PENDING;
                if (read_state_.compare_exchange_strong(last_state, READ_NONE)) {
                    return;
                }
            }

            goto read_loop;
        }

        // If transport is not in started state, try to interrupt the transport.
        if (!__is_status(TRANSPORT_STARTED)) {
            if (pending_send_size_.load(std::memory_order_acquire) == 0) {
                __interrupt_and_trigger_callbacks();
            }
            return;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->post_read() == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("tls_transport: handle read event failed for flow post read task failed");
            __try_doing_disconnected_process();
        }
#else
        PUMP_DEBUG_CHECK(r_tracker_->set_tracked(true));
#endif
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_transport::on_send_event(net::iocp_task_ptr iocp_task) {
#else
    void tls_transport::on_send_event() {
#endif
        auto flow = flow_.get();

#if defined(PUMP_HAVE_IOCP)
        auto ret = flow->send_to_net(iocp_task);
#else
        auto ret = flow->send_to_net();
#endif
        if (ret == flow::FLOW_ERR_AGAIN) {
#if !defined(PUMP_HAVE_IOCP)
            PUMP_DEBUG_CHECK(s_tracker_->set_tracked(true));
#endif
            return;
        } else if (ret == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("tls_transport: handle send event failed for flow send to net failed");
            __try_doing_disconnected_process();
            return;
        }

        // Free last send io buffer.
        last_send_iob_->sub_ref();
        last_send_iob_ = nullptr;

        // If there are more buffers to send, we should send next one immediately.
        if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
            if (!__send_once(flow, false)) {
                PUMP_DEBUG_LOG("tls_transport: handle send event failed for sending once failed");
                __try_doing_disconnected_process();
            }
            return;
        }

        if (__is_status(TRANSPORT_STOPPING)) {
            PUMP_DEBUG_LOG("tls_transport: handle send event failed for transport had being stopped");
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

        if (flow_->has_data_to_read()) {
            __post_channel_event(shared_from_this(), 0);
            return ERROR_OK;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow_->post_read() == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("tls_transport: async read failed for flow post read task failed");
            return ERROR_FAULT;
        }
#else
        if (!__start_read_tracker(shared_from_this())) {
            PUMP_ERR_LOG("tls_transport: async read failed for starting read tracker failed");
            return ERROR_FAULT;
        }
#endif

        return ERROR_OK;
    }

    bool tls_transport::__async_send(toolkit::io_buffer_ptr iob) {
        // Insert buffer to sendlist.
        PUMP_DEBUG_CHECK(sendlist_.push(iob));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(iob->data_size()) > 0) {
            return true;
        }

        if (!__send_once(flow_.get(), true)) {
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                __close_transport_flow();
                __post_channel_event(shared_from_this(), 0);
            }
            return false;
        }

        return true;
    }

    bool tls_transport::__send_once(flow::flow_tls_ptr flow, bool resume) {
        // Get a buffer from sendlist to send.
        PUMP_ASSERT(!last_send_iob_);
        PUMP_DEBUG_CHECK(sendlist_.pop(last_send_iob_));

        // Save last send buffer data size.
        last_send_iob_size_ = last_send_iob_->data_size();

        if (flow->send_to_ssl(last_send_iob_) == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("tls_transport: send once failed for flow send to ssl failed");
            return false;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->post_send() == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("tls_transport: send once failed for flow post send task failed");
            return false;
        }
#else
        auto ret = flow->want_to_send();
        if (ret == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("tls_transport: send once failed for flow want to send failed");
            return false;
        }

        if (!resume) {
            PUMP_DEBUG_CHECK(s_tracker_->set_tracked(true));
            return true;
        }

        if (PUMP_LIKELY(ret == flow::FLOW_ERR_NO)) {
            last_send_iob_->sub_ref();
            last_send_iob_ = nullptr;
            if (pending_send_size_.fetch_sub(last_send_iob_size_, 
                                             std::memory_order_release) == last_send_iob_size_) {
                return true;
            }
        }

        if (!__start_send_tracker(shared_from_this())) {
            PUMP_ERR_LOG("tls_transport: send once failed for starting send tracker failed");
            return false;
        }
#endif
        return true;
    }

    void tls_transport::__try_doing_disconnected_process() {
        // Change transport state from TRANSPORT_STARTED to TRANSPORT_DISCONNECTING.
        __set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING);
        // Interrupt tranport
        __interrupt_and_trigger_callbacks();
    }

    void tls_transport::__clear_send_pockets() {
        if (last_send_iob_) {
            last_send_iob_->sub_ref();
        }

        toolkit::io_buffer_ptr iob;
        while (sendlist_.pop(iob)) {
            iob->sub_ref();
        }
    }

}  // namespace transport
}  // namespace pump
