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

#ifndef pump_transport_channel_h
#define pump_transport_channel_h

#include "pump/service.h"
#include "pump/poll/channel.h"
#include "pump/toolkit/buffer.h"
#include "pump/transport/address.h"
#include "pump/transport/callbacks.h"

namespace pump {
namespace transport {

    namespace flow {
        class flow_base;
    }

    /*********************************************************************************
     * Transport type
     ********************************************************************************/
    const int32_t UDP_TRANSPORT = 0;
    const int32_t TCP_ACCEPTOR = 1;
    const int32_t TCP_DIALER = 2;
    const int32_t TCP_TRANSPORT = 3;
    const int32_t TLS_ACCEPTOR = 4;
    const int32_t TLS_DIALER = 5;
    const int32_t TLS_HANDSHAKER = 6;
    const int32_t TLS_TRANSPORT = 7;

    /*********************************************************************************
     * Transport state
     ********************************************************************************/
    const int32_t TRANSPORT_INITED = 0;
    const int32_t TRANSPORT_STARTING = 1;
    const int32_t TRANSPORT_STARTED = 2;
    const int32_t TRANSPORT_STOPPING = 3;
    const int32_t TRANSPORT_STOPPED = 4;
    const int32_t TRANSPORT_DISCONNECTING = 5;
    const int32_t TRANSPORT_DISCONNECTED = 6;
    const int32_t TRANSPORT_TIMEOUTING = 7;
    const int32_t TRANSPORT_TIMEOUTED = 8;
    const int32_t TRANSPORT_HANDSHAKING = 9;
    const int32_t TRANSPORT_FINISHED = 10;
    const int32_t TRANSPORT_ERROR = 11;

    /*********************************************************************************
     * Transport read state
     ********************************************************************************/
    const int32_t READ_NONE = 0;
    const int32_t READ_INVALID = 1;
    const int32_t READ_PENDING = 2;
    const int32_t READ_ONCE = 3;
    const int32_t READ_LOOP = 4;

    /*********************************************************************************
     * Transport error
     ********************************************************************************/
    const int32_t ERROR_OK = 0;
    const int32_t ERROR_UNSTART = 1;
    const int32_t ERROR_INVALID = 2;
    const int32_t ERROR_DISABLE = 3;
    const int32_t ERROR_AGAIN = 4;
    const int32_t ERROR_FAULT = 5;

    class LIB_PUMP base_channel
      : public service_getter,
        public poll::channel {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_channel(int32_t type, service_ptr sv, int32_t fd) noexcept
            : service_getter(sv),
              poll::channel(fd),
              type_(type),
              transport_state_(TRANSPORT_INITED) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~base_channel() = default;

        /*********************************************************************************
         * Get transport type
         ********************************************************************************/
        PUMP_INLINE int32_t get_type() const {
            return type_;
        }

        /*********************************************************************************
         * Get started status
         ********************************************************************************/
        PUMP_INLINE bool is_started() const {
            return __is_state(TRANSPORT_STARTED);
        }

      protected:
        /*********************************************************************************
         * Set channel state
         ********************************************************************************/
        PUMP_INLINE bool __set_state(int32_t expected, int32_t desired) {
            return transport_state_.compare_exchange_strong(expected, desired);
        }

        /*********************************************************************************
         * Check transport state
         ********************************************************************************/
        PUMP_INLINE bool __is_state(int32_t status) const {
            return transport_state_.load(std::memory_order_acquire) == status;
        }

        /*********************************************************************************
         * Post channel event
         ********************************************************************************/
        PUMP_INLINE void __post_channel_event(poll::channel_sptr &&ch, int32_t event) {
            get_service()->post_channel_event(ch, event);
        }
        PUMP_INLINE void __post_channel_event(poll::channel_sptr &ch, int32_t event) {
            get_service()->post_channel_event(ch, event);
        }

      protected:
        // Transport type
        int32_t type_;
        // Transport state
        std::atomic_int32_t transport_state_;
    };

    class LIB_PUMP base_transport : 
        public base_channel, 
        public std::enable_shared_from_this<base_transport> {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_transport(int32_t type, service_ptr sv, int32_t fd)
            : base_channel(type, sv, fd),
              read_state_(READ_NONE),
              pending_send_size_(0) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~base_transport() {
        }

        /*********************************************************************************
         * Start
         ********************************************************************************/
        virtual int32_t start(service_ptr sv, const transport_callbacks &cbs) = 0;

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() = 0;

        /*********************************************************************************
         * Force stop
         ********************************************************************************/
        virtual void force_stop() = 0;

        /*********************************************************************************
         * Read for once
         ********************************************************************************/
        virtual int32_t read_for_once() {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Read for loop
         ********************************************************************************/
        virtual int32_t read_for_loop() {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Send
         ********************************************************************************/
        virtual int32_t send(const block_t *b, int32_t size) {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Send io buffer
         * The ownership of io buffer will be transferred.
         ********************************************************************************/
        virtual int32_t send(toolkit::io_buffer_ptr iob) {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Send
         ********************************************************************************/
        virtual int32_t send(const block_t *b,
                             int32_t size,
                             const address &address) {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Get pending send buffer size
         ********************************************************************************/
        PUMP_INLINE int32_t get_pending_send_size() const {
            return pending_send_size_.load(std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Get local address
         ********************************************************************************/
        PUMP_INLINE const address& get_local_address() const {
            return local_address_;
        }

        /*********************************************************************************
         * Get remote address
         ********************************************************************************/
        PUMP_INLINE const address& get_remote_address() const {
            return remote_address_;
        }

      protected:
        /*********************************************************************************
         * Channel event callback
         ********************************************************************************/
        virtual void on_channel_event(int32_t ev) override;

      protected:
        /*********************************************************************************
         * Close transport flow
         ********************************************************************************/
        virtual void __close_transport_flow() = 0;

        /*********************************************************************************
         * Chane read state
         ********************************************************************************/
        int32_t __change_read_state(int32_t state);

        /*********************************************************************************
         * Interrupt and trigger callbacks
         ********************************************************************************/
        void __interrupt_and_trigger_callbacks();

#if !defined(PUMP_HAVE_IOCP)
        /*********************************************************************************
         * Start trackers
         ********************************************************************************/
        PUMP_INLINE bool __start_read_tracker() {
            auto tracker = r_tracker_.get();
            if (PUMP_UNLIKELY(!tracker)) {
                tracker = object_create<poll::channel_tracker>(
                    shared_from_this(), poll::TRACK_READ);
                r_tracker_.reset(tracker, object_delete<poll::channel_tracker>);
                if (!get_service()->add_channel_tracker(r_tracker_, READ_POLLER)) {
                    PUMP_WARN_LOG("base_transport: start read tracker failed");
                    return false;
                }
                PUMP_DEBUG_LOG("base_transport: start read tracker");
            } else {
                if (!tracker->get_poller()->resume_channel_tracker(tracker)) {
                    PUMP_WARN_LOG("base_transport: resume read tracker failed");
                    return false;
                }
            }
            return true;
        }
        PUMP_INLINE bool __start_send_tracker() {
            auto tracker = s_tracker_.get();
            if (PUMP_UNLIKELY(!tracker)) {
                tracker = object_create<poll::channel_tracker>(
                    shared_from_this(), poll::TRACK_SEND);
                s_tracker_.reset(tracker, object_delete<poll::channel_tracker>);
                if (!get_service()->add_channel_tracker(s_tracker_, WRITE_POLLER)) {
                    PUMP_WARN_LOG("base_transport: start send tracker failed");
                    return false;
                }
                PUMP_DEBUG_LOG("base_transport: start send tracker");
            } else {
                if (!tracker->get_poller()->resume_channel_tracker(tracker)) {
                    PUMP_WARN_LOG("base_transport: resume send tracker failed");
                    return false;
                }
            }
            return true;
        }

        /*********************************************************************************
         * Stop tracker
         ********************************************************************************/
        PUMP_INLINE void __stop_read_tracker() {
            if (r_tracker_) {
                PUMP_DEBUG_LOG("base_transport: stop read tracker");
                get_service()->remove_channel_tracker(r_tracker_, READ_POLLER);
            }
        }
        PUMP_INLINE void __stop_send_tracker() {
            if (s_tracker_) {
                PUMP_DEBUG_LOG("base_transport: stop send tracker");
                get_service()->remove_channel_tracker(s_tracker_, WRITE_POLLER);
            }
        }

        /*********************************************************************************
         * Resume trackers
         ********************************************************************************/
        PUMP_INLINE bool __resume_read_tracker() {
            PUMP_ASSERT(r_tracker_);
            auto tracker = r_tracker_.get();
            return tracker->get_poller()->resume_channel_tracker(tracker);
        }
        PUMP_INLINE bool __resume_send_tracker() {
            PUMP_ASSERT(s_tracker_);
            auto tracker = s_tracker_.get();
            return tracker->get_poller()->resume_channel_tracker(tracker);
        }
#endif
      protected:
        // Local address
        address local_address_;
        // Remote address
        address remote_address_;

#if !defined(PUMP_HAVE_IOCP)
        // Channel trackers
        poll::channel_tracker_sptr r_tracker_;
        poll::channel_tracker_sptr s_tracker_;
#endif
        // Transport read state
        std::atomic_int32_t read_state_;

        // Pending send buffer size
        std::atomic_int32_t pending_send_size_;

        // Transport callbacks
        transport_callbacks cbs_;
    };

}  // namespace transport
}  // namespace pump

#endif
