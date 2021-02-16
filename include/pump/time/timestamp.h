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
#include "pump/platform.h"

namespace pump {
namespace time {

    /*********************************************************************************
     * Get clock microseconds, just for calculating time difference
     ********************************************************************************/
    LIB_PUMP uint64_t get_clock_microseconds();

    /*********************************************************************************
     * Get clock milliseconds, just for calculating time difference
     ********************************************************************************/
    LIB_PUMP uint64_t get_clock_milliseconds();

    class LIB_PUMP timestamp {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        timestamp() noexcept {
            ms_ = std::chrono::milliseconds(now_time());
        }
        timestamp(uint64_t ms) noexcept {
            ms_ = std::chrono::milliseconds(ms);
        }

        /*********************************************************************************
         * Increase time value
         ********************************************************************************/
        PUMP_INLINE void increase(uint64_t ms) {
            ms_ += std::chrono::milliseconds(ms);
        }

        /*********************************************************************************
         * Reduce time value
         ********************************************************************************/
        PUMP_INLINE void reduce(uint64_t ms) {
            ms_ -= std::chrono::milliseconds(ms);
        }

        /*********************************************************************************
         * Set the time value
         ********************************************************************************/
        PUMP_INLINE void set(uint64_t ms) {
            ms_ = std::chrono::milliseconds(ms);
        }

        /*********************************************************************************
         * Get the time value
         ********************************************************************************/
        PUMP_INLINE uint64_t time() const {
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
        static uint64_t now_time();

        /*********************************************************************************
         * Create now timestamp
         ********************************************************************************/
        PUMP_INLINE static timestamp now() {
            return timestamp(now_time());
        }

      public:
        /*********************************************************************************
         * Overwrite operator =
         ********************************************************************************/
        PUMP_INLINE timestamp &operator=(const timestamp &ts) noexcept {
            ms_ = ts.ms_;
            return *this;
        }

        /*********************************************************************************
         * Overwrite operator <
         ********************************************************************************/
        PUMP_INLINE bool operator<(const timestamp &ts) const noexcept {
            return ms_ < ts.ms_;
        }

        /*********************************************************************************
         * Overwrite operator <=
         ********************************************************************************/
        PUMP_INLINE bool operator<=(const timestamp &ts) const noexcept {
            return ms_ <= ts.ms_;
        }

        /*********************************************************************************
         * Overwrite operator ==
         ********************************************************************************/
        PUMP_INLINE bool operator==(const timestamp &ts) const noexcept {
            return ms_ == ts.ms_;
        }

      private:
        std::chrono::milliseconds ms_;
    };

}  // namespace time
}  // namespace pump

#endif
