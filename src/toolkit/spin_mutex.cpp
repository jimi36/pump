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

#include "pump/toolkit/spin_mutex.h"

namespace pump {
namespace toolkit {

spin_mutex::spin_mutex(int32_t per_loop) noexcept
  : per_loop_(per_loop),
    locked_(false) {
}

void spin_mutex::lock() noexcept {
    int32_t loop = 0;
    bool exp = false;

    while (1) {
        if (!locked_.compare_exchange_strong(exp, true)) {
            break;
        }

        if (loop++ > per_loop_) {
            loop = 0;
            pump_sched_yield();
        }
    }
}

}  // namespace toolkit
}  // namespace pump