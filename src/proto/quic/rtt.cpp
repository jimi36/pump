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

#include "pump/proto/quic/rtt.h"
#include "pump/proto/quic/defaults.h"

namespace pump {
namespace proto {
namespace quic {

    const static int64_t MAX_RTT = 1 << 60;
    const static int64_t DEF_RTT = 100;

    const static float32_t RTT_BETA = 0.25;
    const static float32_t RTT_ALPHA = 0.125;

    rtt::rtt() 
      : inited_(false),
        min_(0),
        latest_(0),
        smoothed_(0),
        mean_deviation_(0),
        max_ack_delay_(0) {
    }

    bool rtt::set_initial_rtt(int64_t r) {
        if (inited_) {
            return false;
        }

        latest_ = r;
        smoothed_ = r;

        return true;
    }

    void rtt::update(
        int64_t sample, 
        int64_t ack_delay, 
        int64_t now) {
        if (sample <= 0 || sample >  MAX_RTT) {
            return;
        }

        if (min_ == 0 || min_ > sample) {
            min_ = sample;
        }

        if (sample - min_ >= ack_delay) {
            sample -= ack_delay;
        }
        latest_ = sample;

        if (!inited_) {
            inited_ = true;
            smoothed_ = sample;
            mean_deviation_ = sample / 2;
        } else {
            mean_deviation_ = (float32_t)mean_deviation_ * (1 - RTT_BETA) + (float32_t)abs(smoothed_- sample) * RTT_BETA;
            smoothed_ = (float32_t)smoothed_ * (1 - RTT_ALPHA) + (float32_t)sample * RTT_ALPHA;
        }
    }

    int64_t rtt::get_pto(bool include_max_ack_delay) {
        if (smoothed_ == 0) {
            return DEF_RTT * 2;
        }

        int64_t pto = smoothed_;
        if (TIMER_GRANULARITY > 4 * mean_deviation_) {
            pto += TIMER_GRANULARITY;
        } else {
            pto += 4 * mean_deviation_;
        }

        if (include_max_ack_delay) {
            pto += max_ack_delay_;
        }

        return pto;
    }

    void rtt::reset() {
        min_ = 0;
        latest_ = 0;
        smoothed_ = 0;
        mean_deviation_ = 0;
    }

}
}
}