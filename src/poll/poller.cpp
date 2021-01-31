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
                                  __poll(3);
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

    bool poller::add_channel_tracker(channel_tracker_sptr &tracker) {
        if (PUMP_UNLIKELY(!started_.load(std::memory_order_relaxed))) {
            PUMP_DEBUG_LOG("poller: add channel tracker failed for poller not started");
            return false;
        }

        tracker->set_poller(this);

        PUMP_DEBUG_CHECK(tracker->start());

        // Install channel tracker
        PUMP_DEBUG_CHECK(__install_channel_tracker(tracker.get()));

        // Set channel tracker installed.
        PUMP_DEBUG_CHECK(!tracker->set_installed(true));

        // Create tracker event
        PUMP_DEBUG_CHECK(
            tevents_.push(object_create<channel_tracker_event>(tracker, TRACKER_EVENT_ADD)));

        // Add pending trakcer event count
        tev_cnt_.fetch_add(1, std::memory_order_release);

        return true;
    }

    void poller::remove_channel_tracker(channel_tracker_sptr &tracker) {
        if (PUMP_UNLIKELY(!started_.load(std::memory_order_relaxed))) {
            PUMP_DEBUG_LOG("poller: remove channel tracker failed for poller not started");
            return;
        }

        if (PUMP_UNLIKELY(!tracker->stop())) {
            PUMP_DEBUG_LOG("poller: remove channel tracker failed for tracker not started");
            return;
        }

        // Wait channel tracker installed.
        while(!tracker->installed());

        // Uninstall channel tracker
        __uninstall_channel_tracker(tracker.get());

        // Create tracker event
        PUMP_DEBUG_CHECK(
            tevents_.push(object_create<channel_tracker_event>(tracker, TRACKER_EVENT_DEL)));

        // Add pending trakcer event count
        tev_cnt_.fetch_add(1, std::memory_order_release);
    }

    bool poller::push_channel_event(channel_sptr &c, int32_t event) {
        if (PUMP_UNLIKELY(!started_.load())) {
            PUMP_DEBUG_LOG("poller: push channel event failed for poller not started");
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

                //PUMP_LOCK_SPOINTER(ch, tracker->get_channel());
                //if (!ch) {
                //    PUMP_DEBUG_LOG("poller: remove trakcer for invalid channel fd=%d", tracker->get_fd());
                //    trackers_.erase(tracker);
                //    break;
                //}

                if (ev->event == TRACKER_EVENT_ADD) {
                    // Apeend to tracker list
                    trackers_[tracker] = ev->tracker;
                } else if (ev->event == TRACKER_EVENT_DEL) {
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
