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

#include "pump/poll/poller.h"

namespace pump {
namespace poll {

    poller::poller() noexcept
      : started_(false), 
        cev_cnt_(0), 
        cevents_(1024), 
        tev_cnt_(0), 
        tevents_(1024) {
    }

    bool poller::start() {
        if (started_.load())
            return false;

        started_.store(true);

        worker_.reset(object_create<std::thread>([&]() {
                          while (started_.load()) {
                              __handle_channel_events();

                              __handle_channel_tracker_events();

                              if (cev_cnt_.load(std::memory_order_acquire) > 0 ||
                                  tev_cnt_.load(std::memory_order_acquire) > 0) {
                                  __poll(0);
                              } else {
                                  __poll(5);
                              }
                          }
                      }),
                      object_delete<std::thread>);

        return true;
    }

    void poller::wait_stopped() {
        if (worker_) {
            worker_->join();
            worker_.reset();
        }
    }

#if !defined(PUMP_HAVE_IOCP)
    bool poller::add_channel_tracker(channel_tracker_sptr &tracker) {
        if (!started_.load(std::memory_order_relaxed)) {
            PUMP_WARN_LOG("poller::add_channel_tracker: poller not started");
            return false;
        }

        if (!tracker->set_tracked(true)) {
            PUMP_WARN_LOG("poller::add_channel_tracker: tracker already tracked");
            PUMP_ASSERT(false);
            return false;
        }

        // Mark tracker started
        PUMP_DEBUG_CHECK(tracker->mark_started(true));

        // Create tracker event
        auto tev = object_create<channel_tracker_event>(tracker, TRACKER_EVENT_ADD);
        PUMP_DEBUG_CHECK(tevents_.push(tev));

        // Add pending trakcer event count
        tev_cnt_.fetch_add(1, std::memory_order_release);

        return true;
    }

    void poller::remove_channel_tracker(channel_tracker_sptr &tracker) {
        // Mark tracker no started
        if (tracker->mark_started(false)) {
            // Create tracker event
            auto tev = object_create<channel_tracker_event>(tracker, TRACKER_EVENT_DEL);
            PUMP_DEBUG_CHECK(tevents_.push(tev));

            // Add pending trakcer event count
            tev_cnt_.fetch_add(1, std::memory_order_release);
        }
    }

    bool poller::resume_channel_tracker(channel_tracker_ptr tracker) {
        if (!tracker->is_started()) {
            PUMP_WARN_LOG("poller::resume_channel_tracker: tracker not started");
            return false;
        }

        if (!tracker->set_tracked(true)) {
            PUMP_WARN_LOG("poller::add_channel_tracker: tracker already tracked");
            return false;
        }

        return __resume_channel_tracker(tracker);
    }
#endif

    bool poller::push_channel_event(channel_sptr &c, int32_t event) {
        if (!started_.load()) {
            PUMP_WARN_LOG("poller::push_channel_event: poller not started");
            return false;
        }

        // Create channel event
        auto cev = object_create<channel_event>(c, event);
        PUMP_DEBUG_CHECK(cevents_.push(cev));

        // Add pending channel event count
        cev_cnt_.fetch_add(1, std::memory_order_release);

        return true;
    }

    void poller::__handle_channel_events() {
        channel_event_ptr ev = nullptr;
        int32_t cnt = cev_cnt_.exchange(0);
        while (cnt > 0) {
            PUMP_DEBUG_CHECK(cevents_.pop(ev));
            PUMP_LOCK_WPOINTER(ch, ev->ch);
            if (ch) {
                ch->handle_channel_event(ev->event);
            }

            object_delete(ev);

            cnt--;
        }
    }

    void poller::__handle_channel_tracker_events() {
        int32_t cnt = tev_cnt_.exchange(0);
        channel_tracker_event_ptr ev = nullptr;
        while (cnt > 0) {
            PUMP_DEBUG_CHECK(tevents_.pop(ev));
            do {
                auto tracker = ev->tracker.get();

                PUMP_LOCK_SPOINTER(ch, tracker->get_channel());
                if (!ch) {
                    PUMP_WARN_LOG(
                        "poller::__handle_channel_tracker_events: channel invalid");
                    trackers_.erase(tracker);
                    break;
                }

                if (ev->event == TRACKER_EVENT_ADD) {
                    // Must be tracked
                    PUMP_ASSERT(tracker->is_tracked());
                    // Apeend to tracker list
                    trackers_[tracker] = ev->tracker;
                    PUMP_DEBUG_CHECK(__add_channel_tracker(tracker));
                } else if (ev->event == TRACKER_EVENT_DEL) {
                    // Remove channel tracker 
                    __remove_channel_tracker(tracker);
                    // Delete from tracker list
                    trackers_.erase(tracker);
                }
            } while (false);

            object_delete(ev);

            cnt--;
        }
    }

}  // namespace poll
}  // namespace pump
