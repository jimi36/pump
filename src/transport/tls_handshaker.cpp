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

#include "pump/transport/tls_handshaker.h"

namespace pump {
namespace transport {

    const int32 TLS_HANDSHAKE_DONE = 0;
    const int32 TLS_HANDSHAKE_DOING = 1;
    const int32 TLS_HANDSHAKE_ERROR = 2;

    tls_handshaker::tls_handshaker() noexcept
        : base_channel(TLS_HANDSHAKER, nullptr, -1) {
    }

    void tls_handshaker::init(int32 fd,
                              bool is_client,
                              void_ptr xcred,
                              const address &local_address,
                              const address &remote_address) {
        local_address_ = local_address;
        remote_address_ = remote_address;

        PUMP_ASSERT(__open_flow(fd, xcred, is_client));
    }

    bool tls_handshaker::start(service_ptr sv,
                               int64 timeout,
                               const tls_handshaker_callbacks &cbs) {
        if (!__set_status(TRANSPORT_INITED, TRANSPORT_STARTING))
            return false;

        PUMP_ASSERT(flow_);

        PUMP_ASSERT(sv != nullptr);
        __set_service(sv);

        PUMP_DEBUG_ASSIGN(cbs.handshaked_cb && cbs.stopped_cb, cbs_, cbs);

        toolkit::defer defer([&]() {
            __close_flow();
#if !defined(PUMP_HAVE_IOCP)
            __stop_tracker();
#endif
            __set_status(TRANSPORT_STARTING, TRANSPORT_ERROR);
        });

        if (flow_->handshake() == flow::FLOW_ERR_ABORT)
            return false;

#if !defined(PUMP_HAVE_IOCP)
        tracker_.reset(
            object_create<poll::channel_tracker>(shared_from_this(), TRACK_NONE),
            object_delete<poll::channel_tracker>);
#endif

        if (flow_->has_data_to_send()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow_->want_to_send() != flow::FLOW_ERR_NO)
                return false;
#else
            tracker_->set_event(TRACK_WRITE);
            if (!get_service()->add_channel_tracker(tracker_, WRITE_POLLER))
                return false;
#endif
        } else {
#if defined(PUMP_HAVE_IOCP)
            if (flow_->want_to_read() != flow::FLOW_ERR_NO)
                return false;
#else
            tracker_->set_event(TRACK_READ);
            if (!get_service()->add_channel_tracker(tracker_, WRITE_POLLER))
                return false;
#endif
        }

        if (!__start_timer(timeout))
            return false;

        defer.clear();

        PUMP_DEBUG_CHECK(__set_status(TRANSPORT_STARTING, TRANSPORT_STARTED));

        return true;
    }

    void tls_handshaker::stop() {
        if (__set_status(TRANSPORT_STARTED, TRANSPORT_STOPPING)) {
            __post_channel_event(shared_from_this(), 0);
            return;
        }

        if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_STOPPING) ||
            __set_status(TRANSPORT_TIMEOUTING, TRANSPORT_STOPPING))
            return;
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_handshaker::on_read_event(void_ptr iocp_task) {
#else
    void tls_handshaker::on_read_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid())
            return;

#if defined(PUMP_HAVE_IOCP)
        if (flow->read_from_net(iocp_task) == flow::FLOW_ERR_ABORT) {
#else
        if (flow->read_from_net() == flow::FLOW_ERR_ABORT) {
#endif
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
                __post_channel_event(shared_from_this(), 0);
            }
            return;
        }

        __process_handshake(flow, tracker_.get());
    }

#if defined(PUMP_HAVE_IOCP)
    void tls_handshaker::on_send_event(void_ptr iocp_task) {
#else
    void tls_handshaker::on_send_event() {
#endif
        auto flow = flow_.get();
        if (!flow->is_valid())
            return;

#if defined(PUMP_HAVE_IOCP)
        auto ret = flow->send_to_net(iocp_task);
#else
        auto ret = flow->send_to_net();
#endif
        if (ret == flow::FLOW_ERR_ABORT) {
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_DISCONNECTING)) {
                __post_channel_event(shared_from_this(), 0);
            }
            return;
        } else if (ret == flow::FLOW_ERR_AGAIN) {
#if !defined(PUMP_HAVE_IOCP)
            __resume_tracker();
#endif
            return;
        }

        __process_handshake(flow, tracker_.get());
    }

    void tls_handshaker::on_channel_event(uint32 ev) {
#if !defined(PUMP_HAVE_IOCP)
        // Stop tracker
        __stop_tracker();
#endif
        // Stop timer
        __stop_timer();

        if (__is_status(TRANSPORT_FINISHED))
            cbs_.handshaked_cb(this, true);
        else if (__is_status(TRANSPORT_ERROR))
            cbs_.handshaked_cb(this, false);
        else if (__set_status(TRANSPORT_TIMEOUTING, TRANSPORT_TIMEOUTED))
            cbs_.handshaked_cb(this, false);
        else if (__set_status(TRANSPORT_DISCONNECTING, TRANSPORT_DISCONNECTED))
            cbs_.handshaked_cb(this, false);
        else if (__set_status(TRANSPORT_STOPPING, TRANSPORT_STOPPED))
            cbs_.stopped_cb(this);

        // Close flow
        __close_flow();
    }

    void tls_handshaker::on_timeout(tls_handshaker_wptr wptr) {
        PUMP_LOCK_WPOINTER(handshaker, wptr);
        if (handshaker == nullptr)
            return;

        if (handshaker->__set_status(TRANSPORT_STARTED, TRANSPORT_TIMEOUTING))
            handshaker->__post_channel_event(std::move(handshaker_locker), 0);
    }

    bool tls_handshaker::__open_flow(int32 fd, void_ptr xcred, bool is_client) {
        // Setup flow
        PUMP_ASSERT(!flow_);
        flow_.reset(object_create<flow::flow_tls>(), object_delete<flow::flow_tls>);

        poll::channel_sptr ch = shared_from_this();
        if (flow_->init(ch, fd, xcred, is_client) != flow::FLOW_ERR_NO)
            return false;

        // Set channel fd
        poll::channel::__set_fd(fd);

        return true;
    }

    void tls_handshaker::__process_handshake(flow::flow_tls_ptr flow,
                                             poll::channel_tracker_ptr tracker) {
        if (flow->handshake() != flow::FLOW_ERR_NO) {
            if (__set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
                __post_channel_event(shared_from_this(), 0);
            return;
        }

        if (flow->has_data_to_send()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_send() != flow::FLOW_ERR_NO &&
                __set_status(TRANSPORT_STARTED, TRANSPORT_ERROR)) {
                __post_channel_event(shared_from_this(), 0);
            }
#else
            if (tracker->is_started()) {
                tracker->set_event(TRACK_WRITE);
                tracker->set_tracked(true);
            }
#endif
            return;
        }

        if (!flow->is_handshaked()) {
#if defined(PUMP_HAVE_IOCP)
            if (flow->want_to_read() != flow::FLOW_ERR_NO &&
                __set_status(TRANSPORT_STARTED, TRANSPORT_ERROR))
                __post_channel_event(shared_from_this(), 0);
#else
            if (flow->send_to_net() != flow::FLOW_ERR_NO &&
                __set_status(TRANSPORT_STARTED, TRANSPORT_ERROR)) {
                __post_channel_event(shared_from_this(), 0);
                return;
            }

            if (tracker->is_started()) {
                tracker->set_event(TRACK_READ);
                tracker->set_tracked(true);
            }
#endif
            return;
        }

        if (__set_status(TRANSPORT_STARTED, TRANSPORT_FINISHED)) {
            __post_channel_event(shared_from_this(), 0);
        }
    }

    bool tls_handshaker::__start_timer(int64 timeout) {
        if (timeout <= 0)
            return true;

        PUMP_ASSERT(!timer_);
        time::timer_callback cb =
            pump_bind(&tls_handshaker::on_timeout, shared_from_this());
        timer_ = time::timer::create_instance(timeout, cb);

        return get_service()->start_timer(timer_);
    }

    void tls_handshaker::__stop_timer() {
        if (timer_)
            timer_->stop();
    }

#if !defined(PUMP_HAVE_IOCP)
    void tls_handshaker::__stop_tracker() {
        PUMP_LOCK_SPOINTER(tracker, tracker_);
        if (tracker && tracker->is_started()) {
            PUMP_DEBUG_CHECK(
                get_service()->remove_channel_tracker(tracker_locker, WRITE_POLLER));
        }
    }

    void tls_handshaker::__resume_tracker() {
        PUMP_LOCK_SPOINTER(tracker, tracker_);
        if (tracker) {
            PUMP_DEBUG_CHECK(get_service()->awake_channel_tracker(tracker, WRITE_POLLER));
        }
    }
#endif

}  // namespace transport
}  // namespace pump
