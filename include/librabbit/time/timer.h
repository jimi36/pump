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

#ifndef librabbit_time_timer_h
#define librabbit_time_timer_h

#include "librabbit/time/timestamp.h"

namespace librabbit {
	namespace time {

		class LIB_EXPORT timeout_notifier
		{
		public:
			/*********************************************************************************
			 * Timer timeout callback
			 ********************************************************************************/
			virtual void on_timer_timeout(void_ptr arg) = 0;
		};
		DEFINE_ALL_POINTER_TYPE(timeout_notifier);

		class LIB_EXPORT timer: 
			public std::enable_shared_from_this<timer>
		{
		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			timer(void_ptr arg, timeout_notifier_sptr &notify, uint64 interval, bool repeat = false);

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			virtual ~timer();

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			bool start();

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			void stop();

			/*********************************************************************************
			 * Handle timeout
			 ********************************************************************************/
			void handle_timeout();

			/*********************************************************************************
			 * Get overtime
			 ********************************************************************************/
			uint64 time() const { return overtime_; }

			/*********************************************************************************
			 * Get starting state
			 ********************************************************************************/
			bool is_started() const { return status_.load() == 1; }

			/*********************************************************************************
			 * Get repeated status
			 ********************************************************************************/
			bool is_repeated() const { return repeated_; }

		private:
			/*********************************************************************************
			 * Set Start state implement
			 ********************************************************************************/
			bool __set_start_state(int32 os, int32 ns);

		private:
			void_ptr arg_;

			// Timer status
			std::atomic_int status_;

			// Repeated status
			volatile bool repeated_;

			// Timeout interval ms
			uint64 interval_;

			// Timeout time ms
			uint64 overtime_;

			// Timeout notifier
			timeout_notifier_wptr notifier_;
		};
		DEFINE_ALL_POINTER_TYPE(timer);

	}
}

#endif
