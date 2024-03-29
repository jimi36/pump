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
    tevents_(1024) {}

bool poller::start() {
    if (started_.load(std::memory_order_relaxed)) {
        return false;
    }
    started_.store(true);

    worker_.reset(
        pump_object_create<std::thread>([&]() {
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
        pump_object_destroy<std::thread>);

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

bool poller::install_channel_tracker(channel_tracker_sptr &tracker) {
    if (pump_unlikely(!started_.load(std::memory_order_relaxed))) {
        pump_debug_log("poller not started");
        return false;
    }

    if (tracker->get_expected_event() != track_none) {
        if (!tracker->track()) {
            pump_debug_log("start tracker failed");
            return false;
        }
    }

    // Create tracker event
    auto ev = pump_object_create<tracker_event>(tracker, tracker_append);
    if (ev == nullptr) {
        pump_warn_log("new tracker event object failed");
        return false;
    }

    // Install channel tracker
    tracker->set_poller(this);
    if (!__install_channel_tracker(tracker.get())) {
        pump_debug_log("install tracker failed");
        tracker->set_poller(nullptr);
        pump_object_destroy(ev);
        return false;
    }

    // Queue tracker event
    if (pump_unlikely(!tevents_.push(ev))) {
        pump_abort_with_log("push tracker event to queue failed");
    }

    // Add pending trakcer event count
    tev_cnt_.fetch_add(1, std::memory_order_release);

    return true;
}

void poller::uninstall_channel_tracker(channel_tracker_sptr &tracker) {
    if (pump_unlikely(!started_.load(std::memory_order_relaxed))) {
        pump_debug_log("poller not started");
        return;
    }

    tracker->untrack();

    // Uninstall channel tracker.
    __uninstall_channel_tracker(tracker.get());

    // Create tracker event
    auto ev = pump_object_create<tracker_event>(tracker, tracker_remove);
    if (ev == nullptr) {
        pump_warn_log("new tracker event object failed");
        return;
    }

    // Queue tracker event
    if (pump_unlikely(!tevents_.push(ev))) {
        pump_abort_with_log("push tracker event to queue failed");
    }

    // Add pending trakcer event count
    tev_cnt_.fetch_add(1, std::memory_order_relaxed);
}

bool poller::start_channel_tracker(channel_tracker_sptr &tracker) {
    if (pump_unlikely(!tracker->track())) {
        pump_debug_log("track tracker failed");
        return false;
    }
    return __start_channel_tracker(tracker.get());
}

bool poller::push_channel_event(
    channel_sptr &c,
    int32_t event,
    void *arg) {
    if (pump_unlikely(!started_.load())) {
        pump_debug_log("poller not started");
        return false;
    }

    // Create channel event
    auto ev = pump_object_create<channel_event>(c, event, arg);
    if (ev == nullptr) {
        pump_warn_log("new channel event object failed");
        return false;
    }

    // Push channel event to queue.
    if (pump_unlikely(!cevents_.push(ev))) {
        pump_abort_with_log("push channel event to queue failed");
    }

    // Add pending channel event count
    cev_cnt_.fetch_add(1, std::memory_order_relaxed);

    return true;
}

void poller::__handle_channel_events() {
    channel_event *ev = nullptr;
    auto cnt = cev_cnt_.exchange(0, std::memory_order_relaxed);
    for (; cnt > 0; cnt--) {
        if (pump_unlikely(!cevents_.pop(ev))) {
            pump_abort_with_log("pop channel event from queue failed");
        }

        auto ch = ev->ch.lock();
        if (ch) {
            ch->handle_channel_event(ev->event, ev->arg);
        }

        pump_object_destroy(ev);
    }
}

void poller::__handle_channel_tracker_events() {
    tracker_event *ev = nullptr;
    auto cnt = tev_cnt_.exchange(0, std::memory_order_relaxed);
    for (; cnt > 0; cnt--) {
        if (pump_unlikely(!tevents_.pop(ev))) {
            pump_abort_with_log("pop tracker event from queue failed");
        }

        if (ev->event == tracker_append) {
            // Apeend to tracker list
            trackers_[ev->tracker.get()] = std::move(ev->tracker);
        } else if (ev->event == tracker_remove) {
            // Delete from tracker list
            trackers_.erase(ev->tracker.get());
        }

        pump_object_destroy(ev);
    }
}

}  // namespace poll
}  // namespace pump
