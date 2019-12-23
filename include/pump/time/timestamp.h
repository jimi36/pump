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
		 * Get microsecond, just for calculating time difference
		 ********************************************************************************/
		LIB_EXPORT extern uint64 get_microsecond();

		class LIB_EXPORT timestamp
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			timestamp() : time_(0) 
			{
			}
			explicit timestamp(uint64 ms_time) : time_(ms_time) 
			{
			}

			/*********************************************************************************
			 * Increase time value
			 ********************************************************************************/
			void increase(uint64 t) { time_ += t; }

			/*********************************************************************************
			 * Reduce time value
			 ********************************************************************************/
			void reduce(uint64 t) { time_ -= t; }

			/*********************************************************************************
			 * Set the time value
			 ********************************************************************************/
			void set(uint64 t) { time_ = t; }

			/*********************************************************************************
			 * Get the time value
			 ********************************************************************************/
			uint64 time() const { return time_; }

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
			std::string format(const std::string &fromat) const;

			/*********************************************************************************
			 * Get now microsecond
			 ********************************************************************************/
			static uint64 now_time();

			/*********************************************************************************
			 * Create now timestamp
			 ********************************************************************************/
			static timestamp now()
			{
				return timestamp(now_time());
			}

		public:
			/*********************************************************************************
			 * Overwrite operator =
			 ********************************************************************************/
			timestamp& operator =(const timestamp& rt)
			{
				time_ = rt.time();
				return *this;
			}

			/*********************************************************************************
			 * Overwrite operator <
			 ********************************************************************************/
			bool operator <(const timestamp& rt)
			{
				return time_ < rt.time();
			}

			/*********************************************************************************
			 * Overwrite operator <=
			 ********************************************************************************/
			bool operator <=(const timestamp& rt)
			{
				return time_ <= rt.time();
			}

			/*********************************************************************************
			 * Overwrite operator ==
			 ********************************************************************************/
			bool operator ==(const timestamp& rt)
			{
				return time_ == rt.time();
			}

		private:
			uint64 time_; /* millisecond */
		};

	}
}

#endif
