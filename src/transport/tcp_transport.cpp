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
          sendlist_(64) {
        next_send_chance_.clear();
    }

    tcp_transport::~tcp_transport() {
        __clear_sendlist();
    }

    void tcp_transport::init(int32 fd,
                             const address &local_address,
                             const address &remote_address) {
        PUMP_DEBUG_CHECK(__open_transport_flow(fd));

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

        // Callbacks
        cbs_ = cbs;

        // Service
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
                while (true) {
                    transport_error err = __async_read(READ_ONCE);
                    if (err == ERROR_FAULT) {
                        __post_channel_event(shared_from_this(), 0);
                        return;
                    } else if (err == ERROR_OK) {
                        __shutdown_transport_flow();
                        return;
                    }
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
                pending_send_size_.store(0xffffffff, std::memory_order_release);
                while (true) {
                    transport_error err = __async_read(READ_ONCE);
                    if (err == ERROR_FAULT) {
                        __post_channel_event(shared_from_this(), 0);
                        return;
                    } else if (err == ERROR_OK) {
                        __shutdown_transport_flow();
                        return;
                    }
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

    transport_error tcp_transport::read_for_once() {
        while (__is_status(TRANSPORT_STARTED, std::memory_order_relaxed)) {
            transport_error err = __async_read(READ_ONCE);
            if (err != ERROR_AGAIN)
                return err;
        }
        return ERROR_UNSTART;
    }

    transport_error tcp_transport::read_for_loop() {
        while (__is_status(TRANSPORT_STARTED, std::memory_order_relaxed)) {
            transport_error err = __async_read(READ_LOOP);
            if (err != ERROR_AGAIN)
                return err;
        }
        return ERROR_UNSTART;
    }

    transport_error tcp_transport::send(c_block_ptr b, uint32 size) {
        if (b == nullptr || size == 0) {
            PUMP_ERR_LOG("transport::tcp_transport::send: buffer invalid ");
            return ERROR_INVALID;
        }

        if (PUMP_UNLIKELY(!__is_status(TRANSPORT_STARTED, std::memory_order_relaxed))) {
            PUMP_ERR_LOG("transport::tcp_transport::send: transport not started");
            return ERROR_UNSTART;
        }

        if (PUMP_UNLIKELY(max_pending_send_size_ > 0 &&
                          pending_send_size_.load(std::memory_order_acquire) >=
                              max_pending_send_size_)) {
            PUMP_WARN_LOG("transport::tcp_transport::send: pending send buffer full");
            return ERROR_AGAIN;
        }

        auto iob = toolkit::io_buffer::create_instance();
        if (PUMP_UNLIKELY(iob == nullptr || !iob->append(b, size))) {
            PUMP_WARN_LOG("transport::tcp_transport::send: new buffer failed");
            if (iob != nullptr)
                iob->sub_ref();
            return ERROR_AGAIN;
        }

        __async_send(iob);

        return ERROR_OK;
    }

#if defined(PUMP_HAVE_IOCP)
    void tcp_transport::on_read_event(void_ptr iocp_task) {
#else
    void tcp_transport::on_read_event() {
#endif
        auto flow = flow_.get();

        // Get old read state and change read state to READ_PENDING.
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

            // If transport is not in started state and no buffer waiting send, then
            // interrupt this transport.
            if (!__is_status(TRANSPORT_STARTED) &&
                pending_send_size_.load(std::memory_order_acquire) <= 0) {
                __interrupt_and_trigger_callbacks();
                return;
            }

            // If transport old read state is READ_ONCE, then change it from READ_PENDING
            // to READ_NONE.
            if (old_state == READ_ONCE &&
                read_state_.compare_exchange_strong(pending_state, READ_NONE))
                return;

#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_read() == flow::FLOW_ERR_ABORT) {
                PUMP_WARN_LOG(
                    "transport::tcp_transport::on_read_event: flow want_to_read failed");
                __try_doing_disconnected_process();
            }
#else
            if (!r_tracker_->is_started()) {
                PUMP_WARN_LOG(
                    "transport::tcp_transport::on_read_event: read tracker not started");
                return;
            }
            PUMP_DEBUG_CHECK(r_tracker_->set_tracked(true));
#endif
        } else {
            PUMP_WARN_LOG("transport::tcp_transport::on_read_event: flow read failed");
            __try_doing_disconnected_process();
        }
    }

#if defined(PUMP_HAVE_IOCP)
    void tcp_transport::on_send_event(void_ptr iocp_task) {
#else
    void tcp_transport::on_send_event() {
#endif
        auto flow = flow_.get();

#if defined(PUMP_HAVE_IOCP)
        auto ret = flow->send(iocp_task);
#else
        auto ret = flow->send();
#endif
        if (ret == flow::FLOW_ERR_AGAIN) {
#if !defined(PUMP_HAVE_IOCP)
            PUMP_DEBUG_CHECK(s_tracker_->set_tracked(true));
#endif
            return;
        } else if (ret == flow::FLOW_ERR_ABORT) {
            PUMP_DEBUG_LOG("transport::tcp_transport::on_send_event: send failed");
            __try_doing_disconnected_process();
            return;
        }

        // If there are more buffers to send, we should send next one immediately.
        if (pending_send_size_.fetch_sub(last_send_iob_size_, std::memory_order_release) >
            last_send_iob_size_) {
            __send_once(flow, false);
            return;
        }

        // We must free next send chance because no more buffers to send.
        next_send_chance_.clear();

        // Sendlist maybe has be inserted buffers at the moment, so we need check
        // and try to get next send chance. If success, we should send next buffer
        // immediately.
        if (pending_send_size_.load(std::memory_order_acquire) > 0 &&
            !next_send_chance_.test_and_set()) {
            if (!__send_once(flow, false)) {
                __try_doing_disconnected_process();
            }
        } else if (__is_status(TRANSPORT_STOPPING)) {
            __interrupt_and_trigger_callbacks();
        }
    }

    bool tcp_transport::__open_transport_flow(int32 fd) {
        // Setup tcp transport flow
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

    transport_error tcp_transport::__async_read(uint32 state) {
        uint32 old_state = __change_read_state(state);
        if (old_state == READ_INVALID)
            return ERROR_AGAIN;
        else if (old_state >= READ_ONCE)
            return ERROR_OK;

#if defined(PUMP_HAVE_IOCP)
        if (flow_->want_to_read() == flow::FLOW_ERR_ABORT) {
            PUMP_ERR_LOG(
                "transport::tcp_transport::__async_read: flow want_to_read fialed");
            return ERROR_FAULT;
        }
#else
        if (!__start_read_tracker(shared_from_this())) {
            PUMP_ERR_LOG(
                "transport::tcp_transport::__async_read: start read tracker fialed");
            return ERROR_FAULT;
        }
#endif
        return ERROR_OK;
    }

    bool tcp_transport::__async_send(toolkit::io_buffer_ptr iob) {
        // Insert buffer to sendlist.
        PUMP_DEBUG_CHECK(sendlist_.push(iob));

        // If there are no more buffers, we should try to get next send chance.
        if (pending_send_size_.fetch_add(iob->data_size(), std::memory_order_release) >
                0 ||
            next_send_chance_.test_and_set())
            return true;

        if (!__send_once(flow_.get(), true)) {
            stop();
            return false;
        }

        return true;
    }

    bool tcp_transport::__send_once(flow::flow_tcp_ptr flow, bool resume) {
        if (last_send_iob_ != nullptr) {
            // Free last send buffer.
            last_send_iob_->sub_ref();
            last_send_iob_ = nullptr;
        }

        // Get a buffer from sendlist to send.
        while (!sendlist_.pop(last_send_iob_)) {
        }

        // Save last send buffer data size.
        last_send_iob_size_ = last_send_iob_->data_size();

        // Try to send the buffer again.
        if (flow->want_to_send(last_send_iob_) != flow::FLOW_ERR_ABORT) {
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

        return false;
    }

    void tcp_transport::__try_doing_disconnected_process() {
        // Change transport state from TRANSPORT_STARTED to TRANSPORT_DISCONNECTING.
        __set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING);
        // Interrupt tranport
        __interrupt_and_trigger_callbacks();
    }

    void tcp_transport::__clear_sendlist() {
        if (last_send_iob_ != nullptr)
            last_send_iob_->sub_ref();

        toolkit::io_buffer_ptr iob;
        while (sendlist_.pop(iob)) {
            iob->sub_ref();
        }
    }

}  // namespace transport
}  // namespace pump
