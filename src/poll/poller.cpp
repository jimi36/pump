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

poller::poller() noexcept :
    started_(false), cev_cnt_(0), cevents_(1024), tev_cnt_(0), tevents_(1024) {}

bool poller::start() {
    if (started_.load(std::memory_order_relaxed)) {
        return false;
    }
    started_.store(true);

    worker_.reset(object_create<std::thread>([&]() {
                      while (started_.load(std::memory_order_relaxed)) {
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

void poller::stop() {
    started_.store(false);
}

void poller::wait_stopped() {
    if (worker_) {
        worker_->join();
        worker_.reset();
    }
}

bool poller::add_channel_tracker(channel_tracker_sptr &tracker) {
    if (PUMP_UNLIKELY(!started_.load(std::memory_order_relaxed))) {
        PUMP_WARN_LOG("poller is not started, can't add channel tracker");
        return false;
    }

    tracker->set_poller(this);

    if (!tracker->start()) {
        PUMP_WARN_LOG("start tracker failed");
        return false;
    }

    // Install channel tracker
    if (!__install_channel_tracker(tracker.get())) {
        PUMP_WARN_LOG("install tracker failed");
        return false;
    }

    // Create tracker event
    PUMP_ABORT_WITH_LOG(
        !tevents_.push(object_create<tracker_event>(tracker, TRACKER_EVENT_ADD)),
        "push adding tracker event to queue failed");

    // Add pending trakcer event count
    tev_cnt_.fetch_add(1, std::memory_order_release);

    return true;
}

void poller::remove_channel_tracker(channel_tracker_sptr &tracker) {
    if (PUMP_UNLIKELY(!started_.load(std::memory_order_relaxed))) {
        PUMP_WARN_LOG("poller is not started, can't remove channel tracker");
        return;
    }

    if (!tracker->stop()) {
        PUMP_WARN_LOG("stop tracker failed");
        return;
    }

    // Uninstall channel tracker.
    __uninstall_channel_tracker(tracker.get());

    // Push tracker event to queue.
    PUMP_ABORT_WITH_LOG(
        !tevents_.push(object_create<tracker_event>(tracker, TRACKER_EVENT_DEL)),
        "push removing tracker event to queue failed");

    // Add pending trakcer event count
    tev_cnt_.fetch_add(1, std::memory_order_relaxed);
}

bool poller::resume_channel_tracker(channel_tracker *tracker) {
    if (PUMP_UNLIKELY(!tracker->track())) {
        PUMP_WARN_LOG("track tracker failed");
        return false;
    }
    return __resume_channel_tracker(tracker);
}

bool poller::push_channel_event(channel_sptr &c, int32_t event) {
    if (PUMP_UNLIKELY(!started_.load())) {
        PUMP_WARN_LOG("poller is not started, can't push channel event");
        return false;
    }

    // Push channel event to queue.
    PUMP_ABORT_WITH_LOG(!cevents_.push(object_create<channel_event>(c, event)),
                        "push channel event to queue failed");

    // Add pending channel event count
    cev_cnt_.fetch_add(1, std::memory_order_relaxed);

    return true;
}

void poller::__handle_channel_events() {
    channel_event *ev = nullptr;
    int32_t cnt = cev_cnt_.exchange(0, std::memory_order_relaxed);
    for (; cnt > 0; cnt--) {
        PUMP_ABORT_WITH_LOG(!cevents_.pop(ev), "pop channel event from queue failed");
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
        PUMP_ABORT_WITH_LOG(!tevents_.pop(ev), "pop tracker event from queue failed");
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
