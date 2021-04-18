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

#if defined(PUMP_HAVE_EPOLL)
#include <sys/epoll.h>
#endif

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
        explicit channel(pump_socket fd) noexcept
          : ctx_(nullptr), 
            fd_(fd) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~channel() = default;

        /*********************************************************************************
         * Get channel fd
         ********************************************************************************/
        PUMP_INLINE pump_socket get_fd() const {
            return fd_;
        }

        /*********************************************************************************
         * Get channel context
         ********************************************************************************/
        PUMP_INLINE void* get_context() const {
            return ctx_;
        }

        /*********************************************************************************
         * Set context
         ********************************************************************************/
        PUMP_INLINE void set_context(void *ctx) {
            ctx_ = ctx;
        }

        /*********************************************************************************
         * Handle io event
         ********************************************************************************/
        PUMP_INLINE void handle_io_event(int32_t ev) {
            if (ev & IO_EVENT_READ) {
                on_read_event();
            } else if (ev & IO_EVENT_SEND) {
                on_send_event();
            }
        }

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
        PUMP_INLINE void __set_fd(pump_socket fd) {
            fd_ = fd;
        }

      protected:
        /*********************************************************************************
         * Read event callback
         ********************************************************************************/
        virtual void on_read_event() {
        }

        /*********************************************************************************
         * Send event callback
         ********************************************************************************/
        virtual void on_send_event() {
        }

        /*********************************************************************************
         * Channel event callback
         ********************************************************************************/
        virtual void on_channel_event(int32_t ev) {
        }

      protected:
        // Channel context
        void *ctx_;
        // Channel fd
        pump_socket fd_;
    };
    DEFINE_ALL_POINTER_TYPE(channel);

    const int32_t TRACK_NONE = (IO_EVENT_NONE);
    const int32_t TRACK_READ = (IO_EVENT_READ);
    const int32_t TRACK_SEND = (IO_EVENT_SEND);
    const int32_t TRACK_BOTH = (IO_EVENT_READ | IO_EVENT_SEND);

    const int32_t TRACKER_EVENT_DEL = 0;
    const int32_t TRACKER_EVENT_ADD = 1;

    const int32_t TRACKER_STATE_STOP    = 0x00;
    const int32_t TRACKER_STATE_TRACK   = 0x01;
    const int32_t TRACKER_STATE_UNTRACK = 0x02;

    class poller;

    class channel_tracker
      : public toolkit::noncopyable {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        channel_tracker(
            channel_sptr &ch, 
            int32_t ev) noexcept
          : state_(TRACKER_STATE_STOP),
              installed_(false),
              expected_event_(ev),
              fd_(ch->get_fd()), 
              ch_(ch),
              pr_(nullptr) {
#if defined(PUMP_HAVE_EPOLL) || defined(PUMP_HAVE_IOCP)
                memset(&ev_, 0, sizeof(ev_));
#endif
        }
        channel_tracker(
            channel_sptr &&ch, 
            int32_t ev) noexcept
          : state_(TRACKER_STATE_STOP),
            installed_(false),
            expected_event_(ev),
            fd_(ch->get_fd()), 
            ch_(ch), 
            pr_(nullptr) {
#if defined(PUMP_HAVE_EPOLL) || defined(PUMP_HAVE_IOCP)
            memset(&ev_, 0, sizeof(ev_));
#endif
        }

        /*********************************************************************************
         * Start
         ********************************************************************************/
        PUMP_INLINE bool start() {
            int32_t expected = TRACKER_STATE_STOP;
            return state_.compare_exchange_strong(
                    expected, 
                    TRACKER_STATE_TRACK,
                    std::memory_order_acquire,
                    std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Stop
         ********************************************************************************/
        PUMP_INLINE bool stop() {
            return state_.exchange(
                    TRACKER_STATE_STOP, 
                    std::memory_order_acquire) != TRACKER_STATE_STOP;
        }

        /*********************************************************************************
         * Get tracked status
         ********************************************************************************/
        PUMP_INLINE bool is_started() const {
            return state_.load(std::memory_order_acquire) != TRACKER_STATE_STOP;
        }

        /*********************************************************************************
         * Track
         ********************************************************************************/
        PUMP_INLINE bool track() {
            int32_t expected = TRACKER_STATE_UNTRACK;
            return state_.compare_exchange_strong(
                    expected, 
                    TRACKER_STATE_TRACK,
                    std::memory_order_acquire,
                    std::memory_order_relaxed);
        }

        /*********************************************************************************
         * untrack
         ********************************************************************************/
        PUMP_INLINE bool untrack() {
            int32_t expected = TRACKER_STATE_TRACK;
            return state_.compare_exchange_strong(
                    expected, 
                    TRACKER_STATE_UNTRACK,
                    std::memory_order_acquire,
                    std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Get tracked status
         ********************************************************************************/
        PUMP_INLINE bool is_tracked() const {
            return state_.load(std::memory_order_acquire) == TRACKER_STATE_TRACK;
        }

        /*********************************************************************************
         * Set installed state
         ********************************************************************************/
        PUMP_INLINE bool set_installed(bool installed) {
            return installed_.exchange(installed, std::memory_order_acquire) == false;
        }

        /*********************************************************************************
         * Check installed state
         ********************************************************************************/
        PUMP_INLINE bool installed() {
            return installed_.load(std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Set expected event
         ********************************************************************************/
        PUMP_INLINE void set_expected_event(int32_t ev) {
            expected_event_ = ev;
        }

        /*********************************************************************************
         * Get expected event
         ********************************************************************************/
        PUMP_INLINE int32_t get_expected_event() const {
            return expected_event_;
        }

        /*********************************************************************************
         * Get event
         ********************************************************************************/
#if defined(PUMP_HAVE_EPOLL)
        PUMP_INLINE struct epoll_event* get_event() {
            return &ev_;
        }
#elif defined(PUMP_HAVE_IOCP)
        PUMP_INLINE AFD_POLL_EVENT* get_event() {
            return &ev_;
        }
#endif
        /*********************************************************************************
         * Get fd
         ********************************************************************************/
        PUMP_INLINE pump_socket get_fd() const {
            return fd_;
        }

        /*********************************************************************************
         * Set channel
         ********************************************************************************/
        PUMP_INLINE void set_channel(channel_sptr &ch) {
            ch_ = ch;
            fd_ = net::get_base_socket(ch->get_fd());
        }

        /*********************************************************************************
         * Get channel
         ********************************************************************************/
        PUMP_INLINE channel_sptr get_channel() {
            return ch_.lock();
        }

        /*********************************************************************************
         * Set poller
         ********************************************************************************/
        PUMP_INLINE void set_poller(poller *pr) {
            pr_ = pr;
        }

        /*********************************************************************************
         * Get poller
         ********************************************************************************/
        PUMP_INLINE poller* get_poller() {
            return pr_;
        }

      private:
        // State
        std::atomic_int32_t state_;
        // Installed state
        std::atomic_bool installed_;
        // Track expected event
        int32_t expected_event_;
        // Track fd
        pump_socket fd_;
        // Channel
        channel_wptr ch_;
        // Poller
        poller *pr_;
#if defined(PUMP_HAVE_EPOLL)
        struct epoll_event ev_;
#elif defined(PUMP_HAVE_IOCP)
        AFD_POLL_EVENT ev_;
#endif
    };
    DEFINE_ALL_POINTER_TYPE(channel_tracker);

}  // namespace poll
}  // namespace pump

#endif
