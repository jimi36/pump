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
        next_send_chance_.clear();
    }

    tls_transport::~tls_transport() {
        __clear_send_pockets();
    }

    void tls_transport::init(flow::flow_tls_sptr &flow,
                             const address &local_address,
                             const address &remote_address) {
        PUMP_DEBUG_ASSIGN(flow, flow_, flow);

        // Flow rebind channel
        poll::channel_sptr ch = shared_from_this();
        flow_->rebind_channel(ch);

        // Set channel fd
        poll::channel::__set_fd(flow->get_fd());

        local_address_ = local_address;
        remote_address_ = remote_address;
    }

    transport_error tls_transport::start(service_ptr sv,
                                         int32 max_pending_send_size,
                                         const transport_callbacks &cbs) {
        if (!flow_) {
            PUMP_ERR_LOG("tls_transport::start: flow invalid");
            return ERROR_INVALID;
        }

        if (sv == nullptr) {
            PUMP_ERR_LOG("tls_transport::start: service invalid");
            return ERROR_INVALID;
        }

        if (!cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("tls_transport::start: callbacks invalid");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG("tls_transport::start: transport had be started before");
            return ERROR_INVALID;
        }

        // Callbacks
        cbs_ = cbs;

        // Service
        __set_service(sv);

        if (max_pending_send_size > 0)
            max_pending_send_size_ = max_pending_send_size;

        // Tls flow maybe read and cached some user data when hankshaking. If there
        // is cached data, transport must callback the cached data to user before
        // reading more data.
        if (flow_->has_data_to_read()) {
            __post_channel_event(shared_from_this(), 0);
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
#if !defined(PUMP_HAVE_IOCP)
                // At first, stopping read tracker immediately.
                __stop_read_tracker();
#endif
                if (pending_send_size_.load() == 0) {
                    __close_flow();
#if !defined(PUMP_HAVE_IOCP)
                    __stop_send_tracker();
#endif
                    __post_channel_event(shared_from_this(), 0);
                }

                return;
            }
        }

        // If in disconnecting status at the moment, it means transport is
        // disconnected but hasn't triggered tracker event callback yet. So we just
        // set stopping status to transport, and when tracker event callback
        // triggered, we will trigger stopped callabck at there.
        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING))
            return;
    }

    void tls_transport::force_stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done. Then
            // tracker event callback will be triggered, we can trigger stopped
            // callabck at there.
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
                __close_flow();
#if !defined(PUMP_HAVE_IOCP)
                __stop_read_tracker();
                __stop_send_tracker();
#endif
                __post_channel_event(shared_from_this(), 0);
                return;
            }
        }

        // If in disconnecting status at the moment, it means transport is
        // disconnected but hasn't triggered tracker event callback yet. So we just
        // set stopping status to transport, and when tracker event callback
        // triggered, we will trigger stopped callabck at there.
        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING))
            return;
    }

    transport_error tls_transport::read_for_once() {
        while (true) {
            if (!is_started()) {
                PUMP_ERR_LOG("tls_transport::read_for_once: transport not started");
                return ERROR_UNSTART;
            }

            uint32 old_state = read_state_.load();
            if (old_state == READ_ONCE || old_state == READ_LOOP) {
                if (!read_state_.compare_exchange_strong(old_state, READ_ONCE))
                    continue;
                break;
            }

            old_state = READ_NONE;
            if (read_state_.compare_exchange_strong(old_state, READ_ONCE)) {
                if (flow_->has_data_to_read()) {
                    __post_channel_event(shared_from_this(), 0);
                } else {
#if defined(PUMP_HAVE_IOCP)
                    if (flow_->want_to_read() == flow::FLOW_ERR_ABORT) {
                        PUMP_ERR_LOG(
                            "tls_transport::read_for_once: flow want_to_read fialed");
                        return ERROR_FAULT;
                    }
#else
                    if (!__start_read_tracker(shared_from_this())) {
                        PUMP_ERR_LOG(
                            "tls_transport::read_for_once: start read tracker fialed");
                        return ERROR_FAULT;
                    }
#endif
                }
                break;
            }

            old_state = READ_PENDING;
            if (read_state_.compare_exchange_strong(old_state, READ_ONCE))
                break;
        }

        return ERROR_OK;
    }

    transport_error tls_transport::read_for_loop() {
        while (true) {
            if (!is_started()) {
                PUMP_ERR_LOG("tls_transport::read_for_loop: transport not started");
                return ERROR_UNSTART;
            }
            uint32 old_state = read_state_.load();
            if (old_state == READ_ONCE || old_state == READ_LOOP) {
                if (!read_state_.compare_exchange_strong(old_state, READ_LOOP))
                    continue;
                break;
            }

            old_state = READ_NONE;
            if (read_state_.compare_exchange_strong(old_state, READ_LOOP)) {
                if (flow_->has_data_to_read()) {
                    __post_channel_event(shared_from_this(), 0);
                } else {
#if defined(PUMP_HAVE_IOCP)
                    if (flow_->want_to_read() == flow::FLOW_ERR_ABORT) {
                        PUMP_ERR_LOG(
                            "tls_transport::read_for_loop: flow want_to_read failed");
                        return ERROR_FAULT;
                    }
#else
                    if (!__start_read_tracker(shared_from_this())) {
                        PUMP_ERR_LOG(
                            "tls_transport::read_for_loop: start read tracker failed");
                        return ERROR_FAULT;
                    }
#endif
                }
                break;
            }

            old_state = READ_PENDING;
            if (read_state_.compare_exchange_strong(old_state, READ_LOOP))
                break;
        }

        return ERROR_OK;
    }

    transport_error tls_transport::send(c_block_ptr b, uint32 size) {
        if (b == nullptr || size == 0) {
            PUMP_ERR_LOG("tls_transport::send: buffer invalid");
            return ERROR_INVALID;
        }

        if (PUMP_UNLIKELY(!is_started())) {
            PUMP_ERR_LOG("tls_transport::send: transport not started");
            return ERROR_UNSTART;
        }

        if (PUMP_UNLIKELY(pending_send_size_.load() >= max_pending_send_size_)) {
            PUMP_WARN_LOG("tls_transport::send: pending send buffer full");
            return ERROR_AGAIN;
        }

        // auto buffer = object_create<flow::buffer>();
        auto iob = toolkit::io_buffer::create_instance();
        if (PUMP_UNLIKELY(iob == nullptr || !iob->append(b, size))) {
            PUMP_WARN_LOG("tls_transport::send: new buffer failed");
            if (iob != nullptr)
                iob->sub_ref();
            return ERROR_AGAIN;
        }

        __async_send(iob);

        return ERROR_OK;
    }

    void tls_transport::on_channel_event(uint32 ev) {
        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED)) {
            cbs_.disconnected_cb();
            return;
        } else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED)) {
            cbs_.stopped_cb();
            return;
        }

        auto flow = flow_.get();
        if (!flow->is_valid()) {
            PUMP_WARN_LOG("tls_transport::on_channel_event: flow invalid");
            return;
        }

        if (!flow->has_data_to_read()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
                PUMP_WARN_LOG(
                    "tls_transport::on_channel_event: flow want_to_read failed");
                __try_doing_disconnected_process();
            }
#else
            if (!__start_read_tracker(shared_from_this())) {
                PUMP_WARN_LOG(
                    "tls_transport::on_channel_event: start read tracker failed");
                __try_doing_disconnected_process();
            }
#endif
            return;
        }

        // Update read state to READ_PENDING.
        uint32 pending_state = READ_PENDING;
        uint32 old_state = read_state_.exchange(pending_state);

        int32 ret = 0;
        int32 size = 0;
        block sslb[MAX_FLOW_BUFFER_SIZE];
        do {
            ret = flow->read_from_ssl(sslb + size, MAX_FLOW_BUFFER_SIZE - size);
            if (size > 0)
                size += ret;
            else
                break;
        } while (flow->has_data_to_read());

        // Has data to callback
        if (size > 0)
            cbs_.read_cb(sslb, size);

        // Read from ssl error
        if (ret == 0) {
            PUMP_WARN_LOG("tls_transport::on_channel_event: flow read_from_ssl failed");
            __try_doing_disconnected_process();
            return;
        }

        // Update read state to READ_NONE and stop continue read if callbacked read data
        // and only read once.
        if (size > 0 && old_state == READ_ONCE) {
            if (read_state_.compare_exchange_strong(pending_state, READ_NONE))
                return;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("tls_transport::on_channel_event: flow want_to_read failed");
            __try_doing_disconnected_process();
        }
#else
        if (!__start_read_tracker(shared_from_this())) {
            PUMP_WARN_LOG("tls_transport::on_channel_event: start read tracker failed");
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
        if (!flow->is_valid()) {
            PUMP_WARN_LOG("tls_transport::on_read_event: flow invalid");
            return;
        }

#if defined(PUMP_HAVE_IOCP)
        auto ret = flow->read_from_net(iocp_task);
#else
        auto ret = flow->read_from_net();
#endif
        if (PUMP_UNLIKELY(ret == flow::FLOW_ERR_ABORT)) {
            PUMP_WARN_LOG("tls_transport::on_read_event: flow read_from_net failed");
            __try_doing_disconnected_process();
            return;
        }

        // Update read state to READ_PENDING.
        uint32 pending_state = READ_PENDING;
        uint32 old_state = read_state_.exchange(pending_state);

        int32 rret = 0;
        int32 size = 0;
        block sslb[MAX_FLOW_BUFFER_SIZE];
        do {
            rret = flow->read_from_ssl(sslb + size, MAX_FLOW_BUFFER_SIZE - size);
            if (size > 0)
                size += rret;
            else
                break;
        } while (flow->has_data_to_read());

        // Has data to callback
        if (size > 0)
            cbs_.read_cb(sslb, size);

        // Read from ssl error
        if (rret == 0) {
            PUMP_WARN_LOG("tls_transport::on_channel_event: flow read_from_ssl failed");
            __try_doing_disconnected_process();
            return;
        }

        // Update read state to READ_NONE and stop continue read if callbacked read data
        // and only read once.
        if (size > 0 && old_state == READ_ONCE) {
            if (read_state_.compare_exchange_strong(pending_state, READ_NONE))
                return;
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("tls_transport::on_read_event: flow want_to_read failed");
            __try_doing_disconnected_process();
        }
#else
        if (!r_tracker_->is_started() || !r_tracker_->set_tracked(true)) {
            PUMP_WARN_LOG("tls_transport::on_read_event: track read failed");
        }
#endif
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_transport::on_send_event(void_ptr iocp_task) {
#else
    void tls_transport::on_send_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid()) {
            PUMP_WARN_LOG("tls_transport::on_send_event: flow invalid");
            return;
        }

#if defined(PUMP_HAVE_IOCP)
        auto ret = flow->send_to_net(iocp_task);
#else
        auto ret = flow->send_to_net();
#endif
        if (ret == flow::FLOW_ERR_AGAIN) {
#if !defined(PUMP_HAVE_IOCP)
            if (!s_tracker_->is_started() || !s_tracker_->set_tracked(true)) {
                PUMP_WARN_LOG("tls_transport::on_send_event: track send failed");
            }
#endif
            return;
        } else if (ret == flow::FLOW_ERR_ABORT) {
            PUMP_WARN_LOG("tls_transport::on_send_event: flow send_to_net failed");
            __try_doing_disconnected_process();
            return;
        }

        // If there are more buffers to send, we should send next one immediately.
        if (pending_send_size_.fetch_sub(last_send_iob_size_) > last_send_iob_size_) {
            __send_once(flow, false);
            return;
        }

        // We must free next send chance because no more buffers to send.
        next_send_chance_.clear();

        // Sendlist maybe has be inserted buffers at the moment, so we need check
        // and try to get next send chance. If success, we should send next buffer
        // immediately.
        if (pending_send_size_.load() > 0 && !next_send_chance_.test_and_set()) {
            __send_once(flow, false);
        } else if (__is_status(TRANSPORT_STOPPING)) {
            __close_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_send_tracker();
#endif
            __post_channel_event(shared_from_this(), 0);
        }
    }

    bool tls_transport::__async_send(toolkit::io_buffer_ptr iob) {
        // Insert buffer to sendlist.
        // PUMP_DEBUG_CHECK(sendlist_.enqueue(iob));
        PUMP_DEBUG_CHECK(sendlist_.push(iob));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(iob->data_size()) > 0 ||
            next_send_chance_.test_and_set())
            return true;

        return __send_once(flow_.get(), true);
    }

    bool tls_transport::__send_once(flow::flow_tls_ptr flow, bool resume) {
        if (last_send_iob_ != nullptr) {
            // Reset last send buffer data size.
            // last_send_buffer_size_ = 0;
            // Free last send buffer.
            last_send_iob_->sub_ref();
            last_send_iob_ = nullptr;
        }

        // Get a buffer from sendlist to send.
        // while (!sendlist_.try_dequeue(last_send_buffer_)) {
        //}
        while (!sendlist_.pop(last_send_iob_)) {
        }

        // Save last send buffer data size.
        last_send_iob_size_ = last_send_iob_->data_size();

        // Send to GnuTLS
        if (flow->send_to_ssl(last_send_iob_) == flow::FLOW_ERR_NO) {
            // Send to net
            if (flow->want_to_send() != flow::FLOW_ERR_ABORT) {
#if !defined(PUMP_HAVE_IOCP)
                if (!resume) {
                    if (!s_tracker_->is_started() || !s_tracker_->set_tracked(true)) {
                        PUMP_ERR_LOG("tls_transport::__send_once: track send failed");
                        return false;
                    }
                    return true;
                }

                if (!__start_send_tracker(shared_from_this())) {
                    PUMP_ERR_LOG("tls_transport::__send_once: start send tracker failed");
                    return false;
                }
#endif
                return true;
            } else {
                PUMP_ERR_LOG(
                    "transport::tls_transport::__send_once: flow want_to_send failed");
            }
        } else {
            PUMP_ERR_LOG(
                "transport::tls_transport::__send_once: flow send_to_ssl failed");
        }

        // Happend error and try disconnecting.
        __try_doing_disconnected_process();

        return false;
    }

    void tls_transport::__try_doing_disconnected_process() {
        if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
            __close_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_read_tracker();
            __stop_send_tracker();
#endif
            __post_channel_event(shared_from_this(), 0);
        }
    }

    void tls_transport::__clear_send_pockets() {
        if (last_send_iob_)
            last_send_iob_->sub_ref();

        toolkit::io_buffer_ptr iob;
        while (sendlist_.pop(iob)) {
            iob->sub_ref();
        }
    }

}  // namespace transport
}  // namespace pump
