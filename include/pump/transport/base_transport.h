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
#include "pump/transport/types.h"
#include "pump/transport/address.h"
#include "pump/transport/callbacks.h"

namespace pump {
namespace transport {

    namespace flow {
        class flow_base;
    }

    class LIB_PUMP base_channel
      : public service_getter,
        public poll::channel {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_channel(
            transport_type type, 
            service *sv, 
            int32_t fd) noexcept
          : service_getter(sv),
            poll::channel(fd),
            type_(type),
            state_(TRANSPORT_INITED) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~base_channel() = default;

        /*********************************************************************************
         * Get transport type
         ********************************************************************************/
        PUMP_INLINE transport_type get_type() const {
            return type_;
        }

        /*********************************************************************************
         * Get started status
         ********************************************************************************/
        PUMP_INLINE bool is_started() const {
            return __is_state(TRANSPORT_STARTED, std::memory_order_relaxed);
        }

      protected:
        /*********************************************************************************
         * Set channel state
         ********************************************************************************/
        PUMP_INLINE bool __set_state(
            transport_state expected, 
            transport_state desired) {
            return state_.compare_exchange_strong(expected, desired);
        }

        /*********************************************************************************
         * Check transport state
         ********************************************************************************/
        PUMP_INLINE bool __is_state(
            transport_state status, 
            std::memory_order order = std::memory_order_acquire) const {
            return state_.load(order) == status;
        }

        /*********************************************************************************
         * Post channel event
         ********************************************************************************/
        PUMP_INLINE bool __post_channel_event(
            poll::channel_sptr &&ch, 
            int32_t event,
            poller_id pid = SEND_POLLER_ID) {
            return get_service()->post_channel_event(ch, event, pid);
        }

      protected:
        // Transport type
        transport_type type_;
        // Transport state
        std::atomic<transport_state> state_;
    };

    class LIB_PUMP base_transport : 
        public base_channel, 
        public std::enable_shared_from_this<base_transport> {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_transport(
            int32_t type, 
            service *sv, 
            int32_t fd)
          : base_channel(type, sv, fd),
            rmode_(READ_MODE_NONE),
            rstate_(READ_NONE),
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
        virtual error_code start(
            service *sv, 
            read_mode mode,
            const transport_callbacks &cbs) {
            return ERROR_FAULT;
        }

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        virtual void stop() {
        }

        /*********************************************************************************
         * Force stop
         ********************************************************************************/
        virtual void force_stop() {
        }

        /*********************************************************************************
         * Read continue for read once mode
         ********************************************************************************/
        virtual error_code read_continue() {
            return ERROR_FAULT;
        }

        /*********************************************************************************
         * Send
         ********************************************************************************/
        virtual error_code send(
            const block_t *b, 
            int32_t size) {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Send io buffer
         * The ownership of io buffer will be transferred.
         ********************************************************************************/
        virtual error_code send(toolkit::io_buffer *iob) {
            return ERROR_DISABLE;
        }

        /*********************************************************************************
         * Send
         ********************************************************************************/
        virtual error_code send(
            const block_t *b,
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
         * Shutdown transport flow
         ********************************************************************************/
        virtual void __shutdown_transport_flow(int32_t how) {
        }

        /*********************************************************************************
         * Close transport flow
         ********************************************************************************/
        virtual void __close_transport_flow() {
        }

        /*********************************************************************************
         * Change read state
         ********************************************************************************/
        bool __change_read_state(read_state from, read_state to);

        /*********************************************************************************
         * Try triggering dissconnected callback
         ********************************************************************************/
        bool __try_triggering_disconnected_callback();

        /*********************************************************************************
         * Trigger disconnected callbacks
         ********************************************************************************/
        bool __trigger_disconnected_callback();

        /*********************************************************************************
         * Trigger stopped callbacks
         ********************************************************************************/
        bool __trigger_stopped_callback();

        /*********************************************************************************
         * Start trackers
         ********************************************************************************/
        PUMP_INLINE bool __start_read_tracker() {
            if (PUMP_UNLIKELY(!r_tracker_)) {
                r_tracker_.reset(
                    object_create<poll::channel_tracker>(
                        shared_from_this(), 
                        poll::TRACK_READ), 
                    object_delete<poll::channel_tracker>);
                if (!r_tracker_ || 
                    !get_service()->add_channel_tracker(r_tracker_, READ_POLLER_ID)) {
                    PUMP_DEBUG_LOG("base_transport: start read tracker failed");
                    return false;
                }
            } else {
                auto poller = r_tracker_->get_poller();
                if (poller == nullptr || 
                    !poller->resume_channel_tracker(r_tracker_.get())) {
                    PUMP_DEBUG_LOG("base_transport: resume read tracker failed");
                    return false;
                }
            }
            return true;
        }
        PUMP_INLINE bool __start_send_tracker() {
            if (PUMP_UNLIKELY(!s_tracker_)) {
                s_tracker_.reset(
                    object_create<poll::channel_tracker>(
                        shared_from_this(), 
                        poll::TRACK_SEND), 
                    object_delete<poll::channel_tracker>);
                if (!s_tracker_ || 
                    !get_service()->add_channel_tracker(s_tracker_, SEND_POLLER_ID)) {
                    PUMP_DEBUG_LOG("base_transport: start send tracker failed");
                    return false;
                }
            } else {
                auto poller = s_tracker_->get_poller();
                if (poller == nullptr || 
                    !poller->resume_channel_tracker(s_tracker_.get())) {
                    PUMP_DEBUG_LOG("base_transport: resume send tracker failed");
                    return false;
                }
            }
            return true;
        }

        /*********************************************************************************
         * Stop tracker
         ********************************************************************************/
        PUMP_INLINE void __stop_read_tracker() {
            if (r_tracker_ && r_tracker_->get_poller() != nullptr) {
                r_tracker_->get_poller()->remove_channel_tracker(r_tracker_);
            }
        }
        PUMP_INLINE void __stop_send_tracker() {
            if (s_tracker_ && s_tracker_->get_poller() != nullptr) {
                s_tracker_->get_poller()->remove_channel_tracker(s_tracker_);
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

      protected:
        // Local address
        address local_address_;
        // Remote address
        address remote_address_;

        // Channel trackers
        poll::channel_tracker_sptr r_tracker_;
        poll::channel_tracker_sptr s_tracker_;

        // Transport read mode
        read_mode rmode_;
        std::atomic<read_state> rstate_;

        // Pending send buffer size
        std::atomic_int32_t pending_send_size_;

        // Transport callbacks
        transport_callbacks cbs_;
    };

}  // namespace transport
}  // namespace pump

#endif
