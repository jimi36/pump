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

#ifndef pump_toolkit_freelock_queue_h
#define pump_toolkit_freelock_queue_h

#include <chrono>

#include <pump/platform.h>
#include <pump/toolkit/features.h>
#include <pump/toolkit/semaphore.h>

namespace pump {
namespace toolkit {

template <typename Q>
class freelock_queue : public noncopyable {
  public:
    // Inner queue type
    typedef Q inner_queue_type;
    // Queue element type
    typedef typename inner_queue_type::element_type element_type;

  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    freelock_queue(uint32_t size = 1024) noexcept
      : queue_(size) {
    }

    /*********************************************************************************
     * Enqueue
     ********************************************************************************/
    pump_inline bool enqueue(const element_type &item) {
        if (pump_likely(queue_.push(item))) {
            semaphone_.signal();
            return true;
        }
        return false;
    }

    pump_inline bool enqueue(element_type &&item) {
        if (pump_likely(queue_.push(item))) {
            semaphone_.signal();
            return true;
        }
        return false;
    }

    /*********************************************************************************
     * Dequeue
     * This will block until dequeue success.
     ********************************************************************************/
    template <typename U>
    bool dequeue(U &item) {
        if (semaphone_.wait()) {
            while (!queue_.pop(item)) {
                continue;
            }
            return true;
        }
        return false;
    }

    /*********************************************************************************
     * Dequeue
     * This will block until dequeue success or timeout.
     ********************************************************************************/
    template <typename U>
    bool dequeue(U &item, int64_t timeout_ns) {
        if (semaphone_.wait(timeout_ns)) {
            while (!queue_.pop(item)) {
                continue;
            }
            return true;
        }
        return false;
    }

    /*********************************************************************************
     * Try dequeue
     * This will return immediately.
     ********************************************************************************/
    template <typename U>
    bool try_dequeue(U &item) {
        if (semaphone_.try_wait()) {
            while (!queue_.pop(item)) {
                continue;
            }
            return true;
        }
        return false;
    }

    /*********************************************************************************
     * Empty
     ********************************************************************************/
    pump_inline bool empty() noexcept {
        return queue_.empty();
    }

  private:
    inner_queue_type queue_;
    light_semaphore semaphone_;
};

}  // namespace toolkit
}  // namespace pump

#endif