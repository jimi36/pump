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

#include "pump/deps.h"

namespace pump {
	namespace time {

		/*********************************************************************************
		 * Get clock microsecond, just for calculating time difference
		 ********************************************************************************/
		LIB_EXPORT extern uint64 get_clock_microsecond();

		/*********************************************************************************
		 * Get clock milliseconds, just for calculating time difference
		 ********************************************************************************/
		LIB_EXPORT extern uint64 get_clock_milliseconds();

		class LIB_EXPORT timestamp
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			timestamp()
			{
				ms_ = std::chrono::milliseconds(now_time());
			}
			timestamp(uint64 ms)
			{
				ms_ = std::chrono::milliseconds(ms);
			}

			/*********************************************************************************
			 * Increase time value
			 ********************************************************************************/
			LIB_FORCEINLINE void increase(uint64 ms) 
			{ ms_ += std::chrono::milliseconds(ms); }

			/*********************************************************************************
			 * Reduce time value
			 ********************************************************************************/
			LIB_FORCEINLINE void reduce(uint64 ms) 
			{ ms_ -= std::chrono::milliseconds(ms); }

			/*********************************************************************************
			 * Set the time value
			 ********************************************************************************/
			LIB_FORCEINLINE void set(uint64 ms) 
			{ ms_ = std::chrono::milliseconds(ms); }

			/*********************************************************************************
			 * Get the time value
			 ********************************************************************************/
			uint64 time() const { return ms_.count(); }

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
			static uint64 now_time();

			/*********************************************************************************
			 * Create now timestamp
			 ********************************************************************************/
			LIB_FORCEINLINE static timestamp now()
			{ return timestamp(now_time()); }

		public:
			/*********************************************************************************
			 * Overwrite operator =
			 ********************************************************************************/
			timestamp& operator =(const timestamp& ts)
			{ ms_ = ts.ms_; return *this; }

			/*********************************************************************************
			 * Overwrite operator <
			 ********************************************************************************/
			bool operator <(const timestamp& ts)
			{ return ms_ < ts.ms_; }

			/*********************************************************************************
			 * Overwrite operator <=
			 ********************************************************************************/
			bool operator <=(const timestamp& ts)
			{ return ms_ <= ts.ms_; }

			/*********************************************************************************
			 * Overwrite operator ==
			 ********************************************************************************/
			bool operator ==(const timestamp& ts)
			{ return ms_ == ts.ms_; }

		private:
			std::chrono::milliseconds ms_;
		};

	}
}

#endif
