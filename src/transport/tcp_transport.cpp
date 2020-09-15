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
          last_send_buffer_size_(0),
          last_send_buffer_(nullptr),
          sendlist_(1024) {
        next_send_chance_.clear();
    }

    tcp_transport::~tcp_transport() {
        __clear_sendlist();
    }

    void tcp_transport::init(int32 fd,
                             const address &local_address,
                             const address &remote_address) {
        PUMP_DEBUG_CHECK(__open_flow(fd));

        local_address_ = local_address;
        remote_address_ = remote_address;
    }

    transport_error tcp_transport::start(service_ptr sv,
                                         int32 max_pending_send_size,
                                         const transport_callbacks &cbs) {
        if (!flow_) {
            PUMP_ERR_LOG("transport::tcp_transport::start: flow invalid");
            return ERROR_INVALID;
        }

        if (sv == nullptr) {
            PUMP_ERR_LOG("transport::tcp_transport::start: service invalid");
            return ERROR_INVALID;
        }

        if (!cbs.read_cb || !cbs.disconnected_cb || !cbs.stopped_cb) {
            PUMP_ERR_LOG("transport::tcp_transport::start: callbacks invalid");
            return ERROR_INVALID;
        }

        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING)) {
            PUMP_ERR_LOG(
                "transport::tcp_transport::start: transport had be started before");
            return ERROR_INVALID;
        }

        // Specifies callbacks
        cbs_ = cbs;

        // Specifies services
        __set_service(sv);

        if (max_pending_send_size > 0)
            max_pending_send_size_ = max_pending_send_size;

        __set_status(TRANSPORT_STARTING, TRANSPORT_STARTED);

        return ERROR_OK;
    }

    void tcp_transport::stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done, Then
            // tracker event callback will be triggered, we can trigger stopped
            // callabck at there.
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
#if !defined(PUMP_HAVE_IOCP)
                // Stop read tracker immediately.
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

    void tcp_transport::force_stop() {
        while (__is_status(TRANSPORT_STARTED)) {
            // When in started status at the moment, stopping can be done, Then
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

    transport_error tcp_transport::read_for_once() {
        while (true) {
            if (!is_started()) {
                PUMP_ERR_LOG(
                    "transport::tcp_transport::read_for_once: transport not started");
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
#if defined(PUMP_HAVE_IOCP)
                if (!flow_->want_to_read() == flow::FLOW_ERR_ABORT) {
                    PUMP_ERR_LOG(
                        "transport::tcp_transport::read_for_once: flow want_to_read "
                        "fialed");
                    return ERROR_FAULT;
                }
#else
                if (!__start_read_tracker(shared_from_this())) {
                    PUMP_ERR_LOG(
                        "transport::tcp_transport::read_for_once: start read tracker "
                        "fialed");
                    return ERROR_FAULT;
                }
#endif
                break;
            }

            old_state = READ_PENDING;
            if (read_state_.compare_exchange_strong(old_state, READ_ONCE))
                break;
        }

        return ERROR_OK;
    }

    transport_error tcp_transport::read_for_loop() {
        while (true) {
            if (!is_started()) {
                PUMP_ERR_LOG(
                    "transport::tcp_transport::read_for_loop: transport not started");
                return ERROR_UNSTART;
            }

            uint32 old_state = read_state_.load();
            if (old_state == READ_ONCE || old_state == READ_LOOP) {
                if (read_state_.compare_exchange_strong(old_state, READ_LOOP))
                    continue;
                break;
            }

            old_state = READ_NONE;
            if (read_state_.compare_exchange_strong(old_state, READ_LOOP)) {
#if defined(PUMP_HAVE_IOCP)
                if (flow_->want_to_read() == flow::FLOW_ERR_ABORT) {
                    PUMP_ERR_LOG(
                        "transport::tcp_transport::read_for_loop: flow want_to_read "
                        "fialed");
                    return ERROR_FAULT;
                }
#else
                if (!__start_read_tracker(shared_from_this())) {
                    PUMP_ERR_LOG(
                        "transport::tcp_transport::read_for_loop: start read tracker "
                        "fialed");
                    return ERROR_FAULT;
                }
#endif
                break;
            }

            old_state = READ_PENDING;
            if (read_state_.compare_exchange_strong(old_state, READ_LOOP))
                break;
        }

        return ERROR_OK;
    }

    transport_error tcp_transport::send(c_block_ptr b, uint32 size) {
        if (b == nullptr || size == 0) {
            PUMP_ERR_LOG("transport::tcp_transport::send: buffer invalid ");
            return ERROR_INVALID;
        }

        if (PUMP_UNLIKELY(!is_started())) {
            PUMP_ERR_LOG("transport::tcp_transport::send: transport not started");
            return ERROR_UNSTART;
        }

        if (PUMP_UNLIKELY(pending_send_size_.load() >= max_pending_send_size_)) {
            PUMP_WARN_LOG("transport::tcp_transport::send: pending send buffer full");
            return ERROR_AGAIN;
        }

        auto buffer = object_create<flow::buffer>();
        if (PUMP_UNLIKELY(buffer == nullptr || !buffer->append(b, size))) {
            PUMP_WARN_LOG("transport::tcp_transport::send: new buffer failed");
            if (buffer != nullptr)
                object_delete(buffer);
            return ERROR_AGAIN;
        }

        __async_send(buffer);

        return ERROR_OK;
    }

#if defined(PUMP_HAVE_IOCP)
    void tcp_transport::on_read_event(void_ptr iocp_task) {
#else
    void tcp_transport::on_read_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid()) {
            PUMP_WARN_LOG("transport::tcp_transport::on_read_event: flow invalid");
            return;
        }

        uint32 pending_state = READ_PENDING;
        uint32 old_state = read_state_.exchange(pending_state);

        int32 size = 0;
#if defined(PUMP_HAVE_IOCP)
        c_block_ptr b = flow->read(iocp_task, &size);
#else
        c_block_ptr b = flow->read(&size);
#endif
        if (PUMP_LIKELY(size > 0)) {
            // Read callback
            cbs_.read_cb(b, size);

            if (old_state == READ_ONCE) {
                if (read_state_.compare_exchange_strong(pending_state, READ_NONE))
                    return;
            }

#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
                PUMP_WARN_LOG(
                    "transport::tcp_transport::on_read_event: flow want_to_read failed");
                __try_doing_disconnected_process();
            }
#else
            if (!r_tracker_->is_started() || !r_tracker_->set_tracked(true)) {
                PUMP_WARN_LOG(
                    "transport::tcp_transport::on_read_event: track read failed");
                __try_doing_disconnected_process();
            }
#endif
        } else {
            __try_doing_disconnected_process();
        }
    }

#if defined(PUMP_HAVE_IOCP)
    void tcp_transport::on_send_event(void_ptr iocp_task) {
#else
    void tcp_transport::on_send_event() {
#endif
        auto flow = flow_.get();
        //if (!flow->is_valid()) {
        //    PUMP_WARN_LOG("transport::tcp_transport::on_send_event: flow invalid");
        //    return;
        //}

#if defined(PUMP_HAVE_IOCP)
        auto ret = flow->send(iocp_task);
#else
        auto ret = flow->send();
#endif
        if (ret == flow::FLOW_ERR_AGAIN) {
#if !defined(PUMP_HAVE_IOCP)
            if (!s_tracker_->set_tracked(true)) {
                PUMP_WARN_LOG(
                    "transport::tcp_transport::on_send_event: track send failed");
                __try_doing_disconnected_process();
            }
#endif
            return;
        } else if (ret == flow::FLOW_ERR_ABORT) {
            PUMP_DEBUG_LOG("transport::tcp_transport::on_send_event: send failed");
            __try_doing_disconnected_process();
            return;
        }

        // If there are more buffers to send, we should send next one immediately.
        if (pending_send_size_.fetch_sub(last_send_buffer_size_) >
            last_send_buffer_size_) {
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

    bool tcp_transport::__open_flow(int32 fd) {
        // Setup flow
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tcp>(), object_delete<flow::flow_tcp>);

        if (flow_->init(shared_from_this(), fd) != flow::FLOW_ERR_NO) {
            PUMP_ERR_LOG("transport::tcp_transport::__open_flow: flow init failed");
            return false;
        }

        // Set channel fd
        poll::channel::__set_fd(fd);

        return true;
    }

    bool tcp_transport::__async_send(flow::buffer_ptr b) {
        // Insert buffer to sendlist.
        PUMP_DEBUG_CHECK(sendlist_.enqueue(b));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(b->data_size()) > 0 ||
            next_send_chance_.test_and_set())
            return true;

        return __send_once(flow_.get(), true);
    }

    bool tcp_transport::__send_once(flow::flow_tcp_ptr flow, bool resume) {
        if (last_send_buffer_ != nullptr) {
            // Reset last send buffer data size.
            last_send_buffer_size_ = 0;
            // Free last send buffer.
            object_delete(last_send_buffer_);
            last_send_buffer_ = nullptr;
        }

        // Get a buffer from sendlist to send.
        PUMP_DEBUG_CHECK(sendlist_.try_dequeue(last_send_buffer_));

        // Save last send buffer data size.
        last_send_buffer_size_ = last_send_buffer_->data_size();

        // Try to send the buffer again.
        if (flow->want_to_send(last_send_buffer_) != flow::FLOW_ERR_ABORT) {
#if defined(PUMP_HAVE_IOCP)
            return true;
#else
            if (!resume) {
                if (!s_tracker_->is_started() || !s_tracker_->set_tracked(true)) {
                    PUMP_ERR_LOG(
                        "transport::tcp_transport::__send_once: track send failed");
                }
                return true;
            }

            if (__start_send_tracker(shared_from_this()))
                return true;

            PUMP_ERR_LOG(
                "transport::tcp_transport::__send_once: start send tracker failed");
#endif
        } else {
            PUMP_ERR_LOG(
                "transport::tcp_transport::__send_once: flow want_to_send failed");
        }

        __try_doing_disconnected_process();

        return false;
    }

    void tcp_transport::__try_doing_disconnected_process() {
        if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
            __close_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_read_tracker();
            __stop_send_tracker();
#endif
            __post_channel_event(shared_from_this(), 0);
        }
    }

    void tcp_transport::__clear_sendlist() {
        if (last_send_buffer_ != nullptr)
            object_delete(last_send_buffer_);

        flow::buffer_ptr buffer;
        while (sendlist_.try_dequeue(buffer)) {
            object_delete(buffer);
        }
    }

}  // namespace transport
}  // namespace pump
