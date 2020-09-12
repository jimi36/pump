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
          last_send_buffer_size_(0),
          last_send_buffer_(nullptr),
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
        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING))
            return ERROR_INVALID;

        PUMP_ASSERT(flow_);

        PUMP_ASSERT(sv != nullptr);
        __set_service(sv);

        PUMP_DEBUG_ASSIGN(
            cbs.read_cb && cbs.disconnected_cb && cbs.stopped_cb, cbs_, cbs);

        toolkit::defer defer([&]() {
            __close_flow();
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (max_pending_send_size > 0)
            max_pending_send_size_ = max_pending_send_size;

        // Tls flow maybe read and cached some user data when hankshaking. If there
        // is cached data, transport must callback the cached data to user before
        // reading more data.
        if (flow_->has_data_to_read()) {
            __post_channel_event(shared_from_this(), 0);
        }

        defer.clear();

        PUMP_DEBUG_CHECK(__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED));

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
            if (!is_started())
                return ERROR_UNSTART;

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
                    if (!flow_->want_to_read() == flow::FLOW_ERR_ABORT)
                        return ERROR_FAULT;
#else
                    if (!__start_read_tracker(shared_from_this()))
                        return ERROR_FAULT;
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
            if (!is_started())
                return ERROR_UNSTART;

            uint32 old_state = read_state_.load();
            if (old_state == READ_ONCE || old_state == READ_LOOP) {
                if (read_state_.compare_exchange_strong(old_state, READ_LOOP))
                    continue;
                break;
            }

            old_state = READ_NONE;
            if (read_state_.compare_exchange_strong(old_state, READ_LOOP)) {
                if (flow_->has_data_to_read()) {
                    __post_channel_event(shared_from_this(), 0);
                } else {
#if defined(PUMP_HAVE_IOCP)
                    if (!flow_->want_to_read() == flow::FLOW_ERR_ABORT)
#else
                    if (!__start_read_tracker(shared_from_this()))
#endif
                        return ERROR_FAULT;
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
        PUMP_ASSERT(b && size > 0);

        if (PUMP_UNLIKELY(!is_started()))
            return ERROR_UNSTART;

        if (PUMP_UNLIKELY(pending_send_size_.load() >= max_pending_send_size_))
            return ERROR_AGAIN;

        auto buffer = object_create<flow::buffer>();
        if (PUMP_UNLIKELY(buffer == nullptr || !buffer->append(b, size))) {
            if (buffer != nullptr)
                object_delete(buffer);
            return ERROR_FAULT;
        }

        __async_send(buffer);

        return ERROR_OK;
    }

    void tls_transport::on_channel_event(uint32 ev) {
        // Wait starting finished
        while (__is_status(TRANSPORT_STARTING)) {
        }

        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED))
            cbs_.disconnected_cb();
        else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
            cbs_.stopped_cb();

        auto flow = flow_.get();
        if (!flow->is_valid())
            return;

        if (!flow->has_data_to_read()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_read() == flow::FLOW_ERR_ABORT)
                __try_doing_disconnected_process();
#else
            __start_read_tracker(shared_from_this());
#endif
            return;
        }

        do {
            uint32 pending_state = READ_PENDING;
            uint32 old_state = read_state_.exchange(pending_state);

            int32 size = 0;
            c_block_ptr b = flow->read_from_ssl(&size);
            if (size > 0 && cbs_.read_cb) {
                cbs_.read_cb(b, size);
            }

            if (old_state == READ_ONCE) {
                if (read_state_.compare_exchange_strong(pending_state, READ_NONE))
                    return;
            }
        } while (flow->has_data_to_read());

#if defined(PUMP_HAVE_IOCP)
        if (flow->want_to_read() == flow::FLOW_ERR_ABORT)
            __try_doing_disconnected_process();
#else
        __start_read_tracker(shared_from_this());
#endif
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_transport::on_read_event(void_ptr iocp_task) {
#else
    void tls_transport::on_read_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid())
            return;

#if defined(PUMP_HAVE_IOCP)
        int32 ret = flow->read_from_net(iocp_task);
#else
        int32 ret = flow->read_from_net();
#endif
        if (PUMP_UNLIKELY(ret == flow::FLOW_ERR_ABORT)) {
            __try_doing_disconnected_process();
            return;
        }

        while (flow->has_data_to_read()) {
            uint32 pending_state = READ_PENDING;
            uint32 old_state = read_state_.exchange(pending_state);

            int32 size = 0;
            c_block_ptr b = flow->read_from_ssl(&size);
            if (size > 0 && cbs_.read_cb) {
                cbs_.read_cb(b, size);
            }

            if (old_state == READ_ONCE) {
                if (read_state_.compare_exchange_strong(pending_state, READ_NONE))
                    return;
            }
        }

#if defined(PUMP_HAVE_IOCP)
        if (flow->want_to_read() == flow::FLOW_ERR_ABORT)
            __try_doing_disconnected_process();
#else
        if (r_tracker_->is_started())
            r_tracker_->set_tracked(true);
#endif
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_transport::on_send_event(void_ptr iocp_task) {
#else
    void tls_transport::on_send_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid())
            return;

#if defined(PUMP_HAVE_IOCP)
        if (flow->send_to_net(iocp_task) == flow::FLOW_ERR_ABORT) {
            __try_doing_disconnected_process();
            return;
        }
#else
        int32 ret = flow->send_to_net();
        if (ret == flow::FLOW_ERR_AGAIN) {
            if (s_tracker_->is_started())
                s_tracker_->set_tracked(true);
            return;
        } else if (ret == flow::FLOW_ERR_ABORT) {
            __try_doing_disconnected_process();
            return;
        }
#endif

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

    bool tls_transport::__async_send(flow::buffer_ptr b) {
        // Insert buffer to sendlist.
        PUMP_DEBUG_CHECK(sendlist_.enqueue(b));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(b->data_size()) != 0 ||
            next_send_chance_.test_and_set())
            return true;

        return __send_once(flow_.get(), true);
    }

    bool tls_transport::__send_once(flow::flow_tls_ptr flow, bool resume) {
        if (last_send_buffer_ != nullptr) {
            // Free last send buffer.
            object_delete(last_send_buffer_);
            last_send_buffer_ = nullptr;

            // Reset last send buffer data size.
            last_send_buffer_size_ = 0;
        }

        // Get a buffer from sendlist to send.
        PUMP_DEBUG_CHECK(sendlist_.try_dequeue(last_send_buffer_));

        // Save last send buffer data size.
        last_send_buffer_size_ = last_send_buffer_->data_size();

        // Try to send the buffer.
        if (flow->send_to_ssl(last_send_buffer_)) {
#if defined(PUMP_HAVE_IOCP)
            return flow->want_to_send() == flow::FLOW_ERR_NO;
#else
            if (!resume) {
                if (s_tracker_->is_started())
                    s_tracker_->set_tracked(true);
                return true;
            }

            if (__start_send_tracker(shared_from_this()))
                return true;
#endif
        }

        // Happend error and try disconnecting.
        __try_doing_disconnected_process();

        return false;
    }

    void tls_transport::__read_tls_data(flow::flow_tls_ptr flow) {
        while (true) {
            int32 size = 0;
            c_block_ptr b = flow->read_from_ssl(&size);
            if (size > 0)
                cbs_.read_cb(b, size);
            else
                break;
        }
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
        if (last_send_buffer_)
            object_delete(last_send_buffer_);

        flow::buffer_ptr buffer;
        while (sendlist_.try_dequeue(buffer)) {
            object_delete(buffer);
        }
    }

}  // namespace transport
}  // namespace pump
