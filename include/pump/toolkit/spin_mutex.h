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

#ifndef pump_toolkit_spin_mutex_h
#define pump_toolkit_spin_mutex_h

#include <atomic>

#include <pump/types.h>
#include <pump/memory.h>

namespace pump {
namespace toolkit {

class pump_lib spin_mutex {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    spin_mutex(int32_t per_loop = 32) pump_noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~spin_mutex() = default;

    /*********************************************************************************
     * Lock
     ********************************************************************************/
    void lock() pump_noexcept;

    /*********************************************************************************
     * Try lock
     ********************************************************************************/
    pump_inline bool try_lock() pump_noexcept {
        bool exp = false;
        return locked_.compare_exchange_strong(exp, true);
    }

    /*********************************************************************************
     * Unlock
     ********************************************************************************/
    pump_inline void unlock() pump_noexcept {
        locked_.store(false);
    }

    /*********************************************************************************
     * Get locked status
     ********************************************************************************/
    pump_inline bool is_locked() const pump_noexcept {
        return locked_.load();
    }

  private:
    int32_t per_loop_;
    std::atomic_bool locked_;
};

}  // namespace toolkit
}  // namespace pump

#endif