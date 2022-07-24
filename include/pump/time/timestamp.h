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

#ifndef pump_time_timestamp_h
#define pump_time_timestamp_h

#include <chrono>
#include <string>

#include "pump/types.h"
#include "pump/memory.h"

namespace pump {
namespace time {

/*********************************************************************************
 * Get clock nanoseconds, just for calculating time difference
 ********************************************************************************/
pump_lib uint64_t get_clock_nanoseconds() pump_noexcept;

/*********************************************************************************
 * Get clock microseconds, just for calculating time difference
 ********************************************************************************/
pump_lib uint64_t get_clock_microseconds() pump_noexcept;

/*********************************************************************************
 * Get clock milliseconds, just for calculating time difference
 ********************************************************************************/
pump_lib uint64_t get_clock_milliseconds() pump_noexcept;

class pump_lib timestamp {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    timestamp() pump_noexcept {
        ms_ = std::chrono::milliseconds(now_time());
    }
    timestamp(uint64_t ms) pump_noexcept {
        ms_ = std::chrono::milliseconds(ms);
    }

    /*********************************************************************************
     * Increase time value
     ********************************************************************************/
    pump_inline void increase(uint64_t ms) pump_noexcept {
        ms_ += std::chrono::milliseconds(ms);
    }

    /*********************************************************************************
     * Reduce time value
     ********************************************************************************/
    pump_inline void reduce(uint64_t ms) pump_noexcept {
        ms_ -= std::chrono::milliseconds(ms);
    }

    /*********************************************************************************
     * Set the time value
     ********************************************************************************/
    pump_inline void set(uint64_t ms) pump_noexcept {
        ms_ = std::chrono::milliseconds(ms);
    }

    /*********************************************************************************
     * Get the time value
     ********************************************************************************/
    pump_inline uint64_t time() const pump_noexcept {
        return ms_.count();
    }

    /*********************************************************************************
     * Get time string as YY-MM-DD hh:mm:ss:ms
     ********************************************************************************/
    std::string to_string() const;

    /*********************************************************************************
     * Get time string
     * YY as year
     * MM as mouth
     * DD as day
     * hh as hour
     * mm as minute
     * ss as second
     * ms as millsecond
     ********************************************************************************/
    std::string format(const std::string &format) const;

    /*********************************************************************************
     * Get now milliseconds
     ********************************************************************************/
    static uint64_t now_time() pump_noexcept;

    /*********************************************************************************
     * Create now timestamp
     ********************************************************************************/
    pump_inline static timestamp now() pump_noexcept {
        return timestamp(now_time());
    }

  public:
    /*********************************************************************************
     * Overwrite operator =
     ********************************************************************************/
    pump_inline timestamp &operator=(const timestamp &ts) pump_noexcept {
        ms_ = ts.ms_;
        return *this;
    }

    /*********************************************************************************
     * Overwrite operator <
     ********************************************************************************/
    pump_inline bool operator<(const timestamp &ts) const pump_noexcept {
        return ms_ < ts.ms_;
    }

    /*********************************************************************************
     * Overwrite operator <=
     ********************************************************************************/
    pump_inline bool operator<=(const timestamp &ts) const pump_noexcept {
        return ms_ <= ts.ms_;
    }

    /*********************************************************************************
     * Overwrite operator ==
     ********************************************************************************/
    pump_inline bool operator==(const timestamp &ts) const pump_noexcept {
        return ms_ == ts.ms_;
    }

  private:
    std::chrono::milliseconds ms_;
};

}  // namespace time
}  // namespace pump

#endif
