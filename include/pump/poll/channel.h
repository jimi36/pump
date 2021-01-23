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

#ifndef pump_poll_channel_h
#define pump_poll_channel_h

#include <atomic>

#include "pump/types.h"
#include "pump/net/iocp.h"
#include "pump/toolkit/features.h"

namespace pump {
namespace poll {

    /*********************************************************************************
     * IO event
     ********************************************************************************/
    const int32_t IO_EVENT_NONE = 0x00;   // none event
    const int32_t IO_EVENT_READ = 0x01;   // read event
    const int32_t IO_EVENT_SEND = 0x02;   // send event
    const int32_t IO_EVENT_ERROR = 0x04;  // error event

    class LIB_PUMP channel
      : public toolkit::noncopyable {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        explicit channel(int32_t fd) noexcept : ctx_(nullptr), fd_(fd) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~channel() = default;

        /*********************************************************************************
         * Get channel fd
         ********************************************************************************/
        PUMP_INLINE int32_t get_fd() const {
            return fd_;
        }

        /*********************************************************************************
         * Get channel context
         ********************************************************************************/
        PUMP_INLINE void_ptr get_context() const {
            return ctx_;
        }

        /*********************************************************************************
         * Set context
         ********************************************************************************/
        PUMP_INLINE void set_context(void_ptr ctx) {
            ctx_ = ctx;
        }

        /*********************************************************************************
         * Handle io event
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        PUMP_INLINE void handle_io_event(uint32_t ev, net::iocp_task_ptr iocp_task) {
            if (ev & IO_EVENT_READ) {
                on_read_event(iocp_task);
            } else if (ev & IO_EVENT_SEND) {
                on_send_event(iocp_task);
            }
        }
#else
        PUMP_INLINE void handle_io_event(uint32_t ev) {
            if (ev & IO_EVENT_READ) {
                on_read_event();
            } else if (ev & IO_EVENT_SEND) {
                on_send_event();
            }
        }
#endif
        /*********************************************************************************
         * Handle channel event
         ********************************************************************************/
        PUMP_INLINE void handle_channel_event(int32_t ev) {
            on_channel_event(ev);
        }

      protected:
        /*********************************************************************************
         * Set channel fd
         ********************************************************************************/
        PUMP_INLINE void __set_fd(int32_t fd) {
            fd_ = fd;
        }

      protected:
        /*********************************************************************************
         * Read event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_read_event(net::iocp_task_ptr iocp_task) {
        }
#else
        virtual void on_read_event() {
        }
#endif
        /*********************************************************************************
         * Send event callback
         ********************************************************************************/
#if defined(PUMP_HAVE_IOCP)
        virtual void on_send_event(net::iocp_task_ptr iocp_task) {
        }
#else
        virtual void on_send_event() {
        }
#endif
        /*********************************************************************************
         * Channel event callback
         ********************************************************************************/
        virtual void on_channel_event(int32_t ev) {
        }

      protected:
        // Channel context
        void_ptr ctx_;
        // Channel fd
        int32_t fd_;
    };
    DEFINE_ALL_POINTER_TYPE(channel);

    const int32_t TRACK_NONE = (IO_EVENT_NONE);
    const int32_t TRACK_READ = (IO_EVENT_READ);
    const int32_t TRACK_SEND = (IO_EVENT_SEND);
    const int32_t TRACK_BOTH = (IO_EVENT_READ | IO_EVENT_SEND);

    const int32_t TRACKER_EVENT_DEL = 0;
    const int32_t TRACKER_EVENT_ADD = 1;

    const int8_t TRACKER_STATE_STOP = 0x00;
    const int8_t TRACKER_STATE_TRACK = 0x01;
    const int8_t TRACKER_STATE_UNTRACK = 0x02;

    class poller;
    DEFINE_RAW_POINTER_TYPE(poller);

    class channel_tracker
      : public toolkit::noncopyable {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        channel_tracker(channel_sptr &ch, int32_t ev) noexcept
            : state_(TRACKER_STATE_STOP),
              event_(ev), 
              fd_(ch->get_fd()), 
              ch_(ch),
              pr_(nullptr) {
        }
        channel_tracker(channel_sptr &&ch, int32_t ev) noexcept
            : state_(TRACKER_STATE_STOP),
              event_(ev), 
              fd_(ch->get_fd()), 
              ch_(ch), 
              pr_(nullptr) {
        }

        /*********************************************************************************
         * Start
         ********************************************************************************/
        PUMP_INLINE bool start() {
            if (PUMP_UNLIKELY(state_ != TRACKER_STATE_STOP)) {
                return false;
            }
            state_ = TRACKER_STATE_TRACK;
            return true;
        }

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        PUMP_INLINE bool stop() {
            if (PUMP_UNLIKELY(state_ == TRACKER_STATE_STOP)) {
                return false;
            }
            state_ = TRACKER_STATE_STOP;
            return true;
        }

        /*********************************************************************************
         * Get tracked status
         ********************************************************************************/
        PUMP_INLINE bool is_started() const {
            return state_ != TRACKER_STATE_STOP;
        }

        /*********************************************************************************
         * Track
         ********************************************************************************/
        PUMP_INLINE bool track() {
            if (PUMP_UNLIKELY(state_ != TRACKER_STATE_UNTRACK)) {
                return false;
            }
            state_ = TRACKER_STATE_TRACK;
            return true;
        }

        /*********************************************************************************
         * untrack
         ********************************************************************************/
        PUMP_INLINE bool untrack() {
            if (PUMP_UNLIKELY(state_ != TRACKER_STATE_TRACK)) {
                return false;
            }
            state_ = TRACKER_STATE_UNTRACK;
            return true;
        }

        /*********************************************************************************
         * Get tracked status
         ********************************************************************************/
        PUMP_INLINE bool is_tracked() const {
            return state_ == TRACKER_STATE_TRACK;
        }

        /*********************************************************************************
         * Set track event
         ********************************************************************************/
        PUMP_INLINE void set_event(int32_t ev) {
            event_ = ev;
        }

        /*********************************************************************************
         * Get track event
         ********************************************************************************/
        PUMP_INLINE int32_t get_event() const {
            return event_;
        }

        /*********************************************************************************
         * Get fd
         ********************************************************************************/
        PUMP_INLINE int32_t get_fd() const {
            return fd_;
        }

        /*********************************************************************************
         * Set channel
         ********************************************************************************/
        PUMP_INLINE void set_channel(channel_sptr &ch) {
            ch_ = ch;
            fd_ = ch->get_fd();
        }

        /*********************************************************************************
         * Get channel
         ********************************************************************************/
        PUMP_INLINE channel_sptr get_channel() const {
            return ch_.lock();
        }

        /*********************************************************************************
         * Set poller
         ********************************************************************************/
        PUMP_INLINE void set_poller(poller_ptr pr) {
            pr_ = pr;
        }

        /*********************************************************************************
         * Get poller
         ********************************************************************************/
        PUMP_INLINE poller_ptr get_poller() {
            return pr_;
        }

      private:
        // State
        int8_t state_;
        // Track event
        int32_t event_;
        // Track fd
        int32_t fd_;
        // Channel
        channel_wptr ch_;
        // Poller
        poller_ptr pr_;
    };
    DEFINE_ALL_POINTER_TYPE(channel_tracker);

}  // namespace poll
}  // namespace pump

#endif
