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

        worker_.reset(
            object_create<std::thread>([&]() {
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

        PUMP_DEBUG_COND_FAIL(
            !tracker->start(), 
            return false);

        // Install channel tracker
        PUMP_DEBUG_COND_FAIL(
            !__install_channel_tracker(tracker.get()), 
            return false);

        // Set channel tracker installed.
        PUMP_DEBUG_COND_FAIL(
            !tracker->set_installed(true),
            return false);

        // Create tracker event
        PUMP_ABORT(
            !tevents_.push(object_create<tracker_event>(tracker, TRACKER_EVENT_ADD)));

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

        // Uninstall channel tracker.
        __uninstall_channel_tracker(tracker.get());

        // Push tracker event to queue.
        PUMP_ABORT(
            !tevents_.push(object_create<tracker_event>(tracker, TRACKER_EVENT_DEL)));

        // Add pending trakcer event count
        tev_cnt_.fetch_add(1, std::memory_order_relaxed);
    }

    bool poller::push_channel_event(
        channel_sptr &c, 
        int32_t event) {
        if (PUMP_UNLIKELY(!started_.load())) {
            PUMP_DEBUG_LOG("poller: push channel event failed for poller not started");
            return false;
        }

        // Push channel event to queue.
        PUMP_ABORT(
            !cevents_.push(object_create<channel_event>(c, event)));

        // Add pending channel event count
        cev_cnt_.fetch_add(1, std::memory_order_relaxed);

        return true;
    }

    void poller::__handle_channel_events() {
        channel_event *ev = nullptr;
        int32_t cnt = cev_cnt_.exchange(0, std::memory_order_relaxed);
        for (; cnt > 0; cnt--) {
            PUMP_DEBUG_CHECK(cevents_.pop(ev));
            auto ch = ev->ch.lock();
            if (ch) {
                ch->handle_channel_event(ev->event);
            }
            object_delete(ev);
        }
    }

    void poller::__handle_channel_tracker_events() {
        tracker_event *ev = nullptr;
        int32_t cnt = tev_cnt_.exchange(0, std::memory_order_relaxed);
        for (; cnt > 0; cnt--) {
            PUMP_DEBUG_CHECK(tevents_.pop(ev));
            if (ev->event == TRACKER_EVENT_ADD) {
                // Apeend to tracker list
                trackers_[ev->tracker.get()] = std::move(ev->tracker);
            } else if (ev->event == TRACKER_EVENT_DEL) {
                // Delete from tracker list
                trackers_.erase(ev->tracker.get());
            }
            object_delete(ev);
        }
    }

}  // namespace poll
}  // namespace pump
