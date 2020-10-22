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
          sendlist_(1024) {
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

    transport_error tls_transport::start(service_ptr sv,
                                         int32 max_pending_send_size,
                                         const transport_callbacks &cbs) {
        if (!flow_) {
            PUMP_ERR_LOG("tls_transport::start: flow invalid");
            return ERROR_INVALID;
        }

        if (!sv) {
            PUMP_ERR_LOG("tls_transport::start: service invalid");
            return ERROR_INVALID;
        }

        if (!cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("tls_transport::start: callbacks invalid");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("tls_transport::start: has started");
            return ERROR_INVALID;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        if (max_pending_send_size > 0) {
            max_pending_send_size_ = max_pending_send_size;
        }

        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        return ERROR_OK;
    }

    void tls_transport::stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done. Then
            // tracker event callback will be triggered, we can trigger stopped
            // callabck at there.
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                if (pending_send_size_.load(std::memory_order_acquire) == 0) {
                    __close_transport_flow();
                    __post_channel_event(shared_from_this(), 0);
                } else {
                    __shutdown_transport_flow();
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

    transport_error tls_transport::read_for_once() {
        while (__is_status(TRANSPORT_STARTED, std::memory_order_relaxed)) {
            transport_error err = __async_read(READ_ONCE);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    transport_error tls_transport::read_for_loop() {
        while (__is_status(TRANSPORT_STARTED, std::memory_order_relaxed)) {
            transport_error err = __async_read(READ_LOOP);
            if (err != ERROR_AGAIN) {
                return err;
            }
        }
        return ERROR_UNSTART;
    }

    transport_error tls_transport::send(c_block_ptr b, uint32 size) {
        if (!b || size == 0) {
            PUMP_ERR_LOG("tls_transport::send: buffer invalid");
            return ERROR_INVALID;
        }

        if (PUMP_UNLIKELY(!__is_status(TRANSPORT_STARTED, std::memory_order_relaxed))) {
            PUMP_ERR_LOG("tls_transport::send: transport not started");
            return ERROR_UNSTART;
        }

        if (PUMP_UNLIKELY(max_pending_send_size_ > 0 &&
                          pending_send_size_.load(std::memory_order_acquire) >=
                              max_pending_send_size_)) {
            PUMP_WARN_LOG("tls_transport::send: send buffer list full");
            return ERROR_AGAIN;
        }

        auto iob = toolkit::io_buffer::create();
        if (PUMP_UNLIKELY(!iob || !iob->append(b, size))) {
            PUMP_WARN_LOG("tls_transport::send: new buffer failed");
            if (!iob) {
                iob->sub_ref();
            }
            return ERROR_AGAIN;
        }

        __async_send(iob);

        return ERROR_OK;
    }

    transport_error tls_transport::send(toolkit::io_buffer_ptr iob) {
        if (!iob || iob->data_size() == 0) {
            PUMP_ERR_LOG("tls_transport::send: io buffer invalid ");
            return ERROR_INVALID;
        }

        if (PUMP_UNLIKELY(!__is_status(TRANSPORT_STARTED, std::memory_order_relaxed))) {
            PUMP_ERR_LOG("tls_transport::send: not started");
            return ERROR_UNSTART;
        }

        if (PUMP_UNLIKELY(max_pending_send_size_ > 0 &&
                          pending_send_size_.load(std::memory_order_acquire) >=
                              max_pending_send_size_)) {
            PUMP_WARN_LOG("tls_transport::send: send buffer list full");
            return ERROR_AGAIN;
        }

        __async_send(iob);

        return ERROR_OK;
    }

    void tls_transport::on_channel_event(uint32 ev) {
        if (!__is_status(TRANSPORT_STARTED)) {
            __interrupt_and_trigger_callbacks();
            return;
        }

        auto flow = flow_.get();

        if (!flow->has_data_to_read()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
                PUMP_WARN_LOG("tls_transport::on_channel_event: want to read failed");
                __try_doing_disconnected_process();
            }
#else
            if (!__start_read_tracker(shared_from_this())) {
                PUMP_WARN_LOG("tls_transport::on_channel_event: start tracker failed");
                __try_doing_disconnected_process();
            }
#endif
            return;
        }

        // Get and change read state to READ_PENDING.
        uint32 pending_state = READ_PENDING;
        uint32 old_state = read_state_.exchange(pending_state);

        int32 ret = 0;
        int32 size = 0;
        block sslb[MAX_FLOW_BUFFER_SIZE];
        do {
            ret = flow->read_from_ssl(sslb + size, MAX_FLOW_BUFFER_SIZE - size);
            if (ret > 0) {
                size += ret;
                if (size == MAX_FLOW_BUFFER_SIZE) {
                    cbs_.read_cb(sslb, size);
                    size = 0;
                }
            } else {
                break;
            }
        } while (flow->has_data_to_read());

        // Read callback
        if (PUMP_LIKELY(size > 0)) {
            cbs_.read_cb(sslb, size);
        }

        // Read data from ssl failed
        if (ret == 0) {
            PUMP_WARN_LOG("tls_transport::on_channel_event: read from ssl failed");
            __try_doing_disconnected_process();
            return;
        }

        // If transport is not in started state and no buffer waiting send, then
        // interrupt this transport.
        if (!__is_status(TRANSPORT_STARTED) &&
            pending_send_size_.load(std::memory_order_acquire) <= 0) {
            __interrupt_and_trigger_callbacks();
            return;
        }

        // If old read state is READ_ONCE, then change it to READ_NONE.
        if (size > 0 && old_state == READ_ONCE) {
            if (read_state_.compare_exchange_strong(pending_state, READ_NONE)) {
                return;
            }
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("tls_transport::on_channel_event: want to read failed");
            __try_doing_disconnected_process();
        }
#else
        if (!__start_read_tracker(shared_from_this())) {
            PUMP_WARN_LOG("tls_transport::on_channel_event: start tracker failed");
            __try_doing_disconnected_process();
        }
#endif
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_transport::on_read_event(void_ptr iocp_task) {
#else
    void tls_transport::on_read_event() {
#endif
        auto flow = flow_.get();

#if defined(PUMP_HAVE_IOCP)
        auto ret = flow->read_from_net(iocp_task);
#else
        auto ret = flow->read_from_net();
#endif
        if (PUMP_UNLIKELY(ret == flow::FLOW_ERR_ABORT)) {
            PUMP_WARN_LOG("tls_transport::on_read_event: read from net failed");
            __try_doing_disconnected_process();
            return;
        }

        // Get old read state and change read state to READ_PENDING.
        uint32 pending_state = READ_PENDING;
        uint32 old_state = read_state_.exchange(pending_state);

        int32 rret = 0;
        int32 size = 0;
        block sslb[MAX_FLOW_BUFFER_SIZE];
        do {
            rret = flow->read_from_ssl(sslb + size, MAX_FLOW_BUFFER_SIZE - size);
            if (rret > 0) {
                size += rret;
                if (size == MAX_FLOW_BUFFER_SIZE) {
                    cbs_.read_cb(sslb, size);
                    size = 0;
                }
            } else {
                break;
            }
        } while (flow->has_data_to_read());

        // Has data to callback
        if (PUMP_LIKELY(size > 0)) {
            cbs_.read_cb(sslb, size);
        }

        // Read data from ssl failed
        if (rret == 0) {
            PUMP_WARN_LOG("tls_transport::on_read_event: read from ssl failed");
            __try_doing_disconnected_process();
            return;
        }

        // If old read state is READ_ONCE, then change it to READ_NONE.
        if (size > 0 && old_state == READ_ONCE &&
            read_state_.compare_exchange_strong(pending_state, READ_NONE)) {
            return;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("tls_transport::on_read_event: want to read failed");
            __try_doing_disconnected_process();
        }
#else
        PUMP_DEBUG_CHECK(r_tracker_->set_tracked(true));
#endif
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_transport::on_send_event(void_ptr iocp_task) {
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
            PUMP_WARN_LOG("tls_transport::on_send_event: send to net failed");
            __try_doing_disconnected_process();
            return;
        }

        // If there are more buffers to send, we should send next one immediately.
        if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
            if (!__send_once(flow, false)) {
                PUMP_DEBUG_LOG("tls_transport::on_send_event: send once failed");
                __try_doing_disconnected_process();
            }
            return;
        }

        if (__is_status(TRANSPORT_STOPPING)) {
            PUMP_DEBUG_LOG("tls_transport::on_send_event: interrupt and callback");
            __interrupt_and_trigger_callbacks();
        }
    }

    transport_error tls_transport::__async_read(uint32 state) {
        uint32 old_state = __change_read_state(state);
        if (old_state == READ_INVALID) {
            return ERROR_AGAIN;
        } else if (old_state >= READ_ONCE) {
            return ERROR_OK;
        }

        if (flow_->has_data_to_read()) {
            __post_channel_event(shared_from_this(), 0);
            return ERROR_OK;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow_->want_to_read() == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("tls_transport::__async_read: want to read failed");
            return ERROR_FAULT;
        }
#else
        if (!__start_read_tracker(shared_from_this())) {
            PUMP_ERR_LOG("tls_transport::__async_read: start tracker failed");
            return ERROR_FAULT;
        }
#endif

        return ERROR_OK;
    }

    bool tls_transport::__async_send(toolkit::io_buffer_ptr iob) {
        // Insert buffer to sendlist.
        // PUMP_DEBUG_CHECK(sendlist_.enqueue(iob));
        PUMP_DEBUG_CHECK(sendlist_.push(iob));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(iob->data_size(), std::memory_order_release) >
            0) {
            return true;
        }

        if (!__send_once(flow_.get(), true)) {
            stop();
            return false;
        }

        return true;
    }

    bool tls_transport::__send_once(flow::flow_tls_ptr flow, bool resume) {
        if (last_send_iob_) {
            // Reset last send buffer data size.
            last_send_iob_->sub_ref();
            last_send_iob_ = nullptr;
        }

        // Get a buffer from sendlist to send.
        PUMP_DEBUG_CHECK(sendlist_.pop(last_send_iob_));

        // Save last send buffer data size.
        last_send_iob_size_ = last_send_iob_->data_size();

        if (flow->send_to_ssl(last_send_iob_) == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("tls_transport::__send_once: send to ssl failed");
            return false;
        }

        auto ret = flow->want_to_send();
        if (ret == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG("tls_transport::__send_once: want to send failed");
            return false;
        }

#if !defined(PUMP_HAVE_IOCP)
        if (!resume) {
            PUMP_DEBUG_CHECK(s_tracker_->set_tracked(true));
            return true;
        }

        if (PUMP_LIKELY(ret == flow::FLOW_ERR_NO)) {
            last_send_iob_->sub_ref();
            last_send_iob_ = nullptr;
            if (pending_send_size_.fetch_sub(last_send_iob_size_) ==
                last_send_iob_size_) {
                return true;
            }
        }

        if (!__start_send_tracker(shared_from_this())) {
            PUMP_ERR_LOG("tls_transport::__send_once: start tracker failed");
            return true;
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
