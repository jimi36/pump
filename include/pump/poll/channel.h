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
    const int32 IO_EVENT_NONE = 0x00;   // none event
    const int32 IO_EVENT_READ = 0x01;   // read event
    const int32 IO_EVENT_SEND = 0x02;   // send event
    const int32 IO_EVENT_ERROR = 0x04;  // error event

    /*********************************************************************************
     * Channel opt type
     ********************************************************************************/
    enum channel_opt_type {
        CH_OPT_NONE = 0x00,
        CH_OPT_APPEND = 0x01,
        CH_OPT_UPDATE = 0x02,
        CH_OPT_DELETE = 0x03
    };

    class LIB_PUMP channel : public toolkit::noncopyable {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        explicit channel(int32 fd) noexcept : ctx_(nullptr), fd_(fd) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~channel() = default;

        /*********************************************************************************
         * Get channel fd
         ********************************************************************************/
        PUMP_INLINE int32 get_fd() const {
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
        PUMP_INLINE void handle_io_event(uint32 ev, net::iocp_task_ptr iocp_task) {
            if (ev & IO_EVENT_READ) {
                on_read_event(iocp_task);
            } else if (ev & IO_EVENT_SEND) {
                on_send_event(iocp_task);
            }
        }
#else
        PUMP_INLINE void handle_io_event(uint32 ev) {
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
        PUMP_INLINE void handle_channel_event(int32 ev) {
            on_channel_event(ev);
        }

      protected:
        /*********************************************************************************
         * Set channel fd
         ********************************************************************************/
        PUMP_INLINE void __set_fd(int32 fd) {
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
        virtual void on_channel_event(uint32 ev) {
        }

      protected:
        // Channel context
        void_ptr ctx_;
        // Channel fd
        int32 fd_;
    };
    DEFINE_ALL_POINTER_TYPE(channel);

    const int32 TRACK_NONE = (IO_EVENT_NONE);
    const int32 TRACK_READ = (IO_EVENT_READ);
    const int32 TRACK_SEND = (IO_EVENT_SEND);
    const int32 TRACK_BOTH = (IO_EVENT_READ | IO_EVENT_SEND);

    const int32 TRACKER_EVENT_DEL = 0;
    const int32 TRACKER_EVENT_ADD = 1;

    class channel_tracker : public toolkit::noncopyable {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        channel_tracker(channel_sptr &ch, int32 ev) noexcept
            : started_(false), 
              tracked_(false), 
              event_(ev), 
              fd_(ch->get_fd()), 
              ch_(ch) {
        }
        channel_tracker(channel_sptr &&ch, int32 ev) noexcept
            : started_(false), 
              tracked_(false), 
              event_(ev), 
              fd_(ch->get_fd()), 
              ch_(ch) {
        }

        /*********************************************************************************
         * Mark started
         ********************************************************************************/
        PUMP_INLINE bool mark_started(bool started) {
            bool expected = !started;
            return started_.compare_exchange_strong(
                expected, started, std::memory_order_acquire, std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Get tracked status
         ********************************************************************************/
        PUMP_INLINE bool is_started() const {
            return started_.load(std::memory_order_acquire);
        }

        /*********************************************************************************
         * Set tracked state
         ********************************************************************************/
        PUMP_INLINE bool set_tracked(bool tracked) {
            bool expected = !tracked;
            return tracked_.compare_exchange_strong(
                expected, tracked, std::memory_order_acquire, std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Get tracked status
         ********************************************************************************/
        PUMP_INLINE bool is_tracked() const {
            return tracked_.load(std::memory_order_acquire);
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
         * Get fd
         ********************************************************************************/
        PUMP_INLINE int32 get_fd() const {
            return fd_;
        }

        /*********************************************************************************
         * Set track event
         ********************************************************************************/
        PUMP_INLINE void set_event(int32 ev) {
            event_ = ev;
        }

        /*********************************************************************************
         * Get track event
         ********************************************************************************/
        PUMP_INLINE int32 get_event() const {
            return event_;
        }

      private:
        // Added to poller state
        std::atomic_bool started_;
        // Tracked state
        std::atomic_bool tracked_;
        // Track event
        int32 event_;
        // Track fd
        int32 fd_;
        // Channel
        channel_wptr ch_;
    };
    DEFINE_ALL_POINTER_TYPE(channel_tracker);

}  // namespace poll
}  // namespace pump

#endif
