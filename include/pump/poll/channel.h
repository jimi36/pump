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

#include <pump/types.h>
#include <pump/net/iocp.h>
#include <pump/toolkit/features.h>

namespace pump {
namespace poll {

/*********************************************************************************
 * IO event
 ********************************************************************************/
const int32_t io_none = 0x00;   // none event
const int32_t io_read = 0x01;   // read event
const int32_t io_send = 0x02;   // send event
const int32_t io_error = 0x04;  // error event

class pump_lib channel : public toolkit::noncopyable {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    explicit channel(pump_socket fd) noexcept
      : ctx_(nullptr), fd_(fd) {}

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~channel() = default;

    /*********************************************************************************
     * Get channel fd
     ********************************************************************************/
    pump_inline pump_socket get_fd() const {
        return fd_;
    }

    /*********************************************************************************
     * Get channel context
     ********************************************************************************/
    pump_inline void *get_context() const {
        return ctx_;
    }

    /*********************************************************************************
     * Set context
     ********************************************************************************/
    pump_inline void set_context(void *ctx) {
        ctx_ = ctx;
    }

    /*********************************************************************************
     * Handle io event
     ********************************************************************************/
    pump_inline void handle_io_event(int32_t ev) {
        if (ev & io_read) {
            on_read_event();
        } else if (ev & io_send) {
            on_send_event();
        }
    }

    /*********************************************************************************
     * Handle channel event
     ********************************************************************************/
    pump_inline void handle_channel_event(int32_t ev, void *arg) {
        on_channel_event(ev, arg);
    }

  protected:
    /*********************************************************************************
     * Set channel fd
     ********************************************************************************/
    pump_inline void __set_fd(pump_socket fd) {
        fd_ = fd;
    }

  protected:
    /*********************************************************************************
     * Read event callback
     ********************************************************************************/
    virtual void on_read_event() {}

    /*********************************************************************************
     * Send event callback
     ********************************************************************************/
    virtual void on_send_event() {}

    /*********************************************************************************
     * Channel event callback
     ********************************************************************************/
    virtual void on_channel_event(int32_t ev, void *arg) {}

  protected:
    // Channel context
    void *ctx_;
    // Channel fd
    pump_socket fd_;
};
DEFINE_SMART_POINTERS(channel);

const int32_t track_none = (io_error);
const int32_t track_read = (io_read);
const int32_t track_send = (io_send);
const int32_t track_both = (io_read | io_send);

const int32_t tracker_remove = 0;
const int32_t tracker_append = 1;

const int32_t tracker_idle = 0x00;
const int32_t tracker_tracking = 0x02;

class poller;

class pump_lib channel_tracker : public toolkit::noncopyable {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    channel_tracker(channel_sptr &ch, int32_t ev) noexcept
      : state_(tracker_idle),
        expected_event_(ev),
        fd_(ch->get_fd()),
        ch_(ch),
        pr_(nullptr) {
#if defined(PUMP_HAVE_EPOLL) || defined(PUMP_HAVE_IOCP)
        memset(&ev_, 0, sizeof(ev_));
#endif
    }
    channel_tracker(channel_sptr &&ch, int32_t ev) noexcept
      : state_(tracker_idle),
        expected_event_(ev),
        fd_(ch->get_fd()),
        ch_(ch),
        pr_(nullptr) {
#if defined(PUMP_HAVE_EPOLL) || defined(PUMP_HAVE_IOCP)
        memset(&ev_, 0, sizeof(ev_));
#endif
    }

    /*********************************************************************************
     * Track
     ********************************************************************************/
    pump_inline bool track() {
        int32_t expected = tracker_idle;
        return state_.compare_exchange_strong(expected, tracker_tracking);
    }

    /*********************************************************************************
     * untrack
     ********************************************************************************/
    pump_inline bool untrack() {
        int32_t expected = tracker_tracking;
        return state_.compare_exchange_strong(expected, tracker_idle);
    }

    /*********************************************************************************
     * Get tracked status
     ********************************************************************************/
    pump_inline bool is_tracked() const {
        return state_.load() == tracker_tracking;
    }

    /*********************************************************************************
     * Set expected event
     ********************************************************************************/
    pump_inline void set_expected_event(int32_t ev) {
        expected_event_ = ev;
    }

    /*********************************************************************************
     * Get expected event
     ********************************************************************************/
    pump_inline int32_t get_expected_event() const {
        return expected_event_;
    }

    /*********************************************************************************
     * Get event
     ********************************************************************************/
#if defined(PUMP_HAVE_EPOLL)
    pump_inline struct epoll_event *get_event() {
        return &ev_;
    }
#elif defined(PUMP_HAVE_IOCP)
    pump_inline AFD_POLL_EVENT *get_event() {
        return &ev_;
    }
#endif
    /*********************************************************************************
     * Get fd
     ********************************************************************************/
    pump_inline pump_socket get_fd() const {
        return fd_;
    }

    /*********************************************************************************
     * Set channel
     ********************************************************************************/
    pump_inline void set_channel(channel_sptr &ch) {
        fd_ = net::get_base_socket(ch->get_fd());
        ch_ = ch;
    }

    /*********************************************************************************
     * Get channel
     ********************************************************************************/
    pump_inline channel_sptr get_channel() {
        return ch_.lock();
    }

    /*********************************************************************************
     * Set poller
     ********************************************************************************/
    pump_inline void set_poller(poller *pr) {
        pr_ = pr;
    }

    /*********************************************************************************
     * Get poller
     ********************************************************************************/
    pump_inline poller *get_poller() {
        return pr_;
    }

  private:
    // State
    std::atomic_int32_t state_;
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
DEFINE_SMART_POINTERS(channel_tracker);

}  // namespace poll
}  // namespace pump

#endif
