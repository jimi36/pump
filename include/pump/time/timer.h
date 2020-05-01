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

#ifndef pump_time_timer_h
#define pump_time_timer_h

#include "pump/utils/features.h"
#include "pump/time/timestamp.h"

namespace pump {
	namespace time {

		typedef function::function<void()> timer_callback;

		class LIB_EXPORT timer: 
			public utils::noncopyable,
			public std::enable_shared_from_this<timer>
		{
		protected:
			friend class timer_queue;

		public:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			timer(
				const timer_callback &cb,
				uint64 interval,
				bool repeated = false
			);

			/*********************************************************************************
			 * Deconstructor
			 ********************************************************************************/
			~timer() = default;

			/*********************************************************************************
			 * Stop
			 ********************************************************************************/
			void stop();

			/*********************************************************************************
			 * Handle timeout
			 ********************************************************************************/
			void handle_timeout(void_ptr tq);

			/*********************************************************************************
			 * Get overtime
			 ********************************************************************************/
			LIB_FORCEINLINE uint64 time() const 
			{ return overtime_; }

			/*********************************************************************************
			 * Get starting state
			 ********************************************************************************/
			LIB_FORCEINLINE bool is_started() const 
			{ return status_.load() == 1; }

			/*********************************************************************************
			 * Get repeated status
			 ********************************************************************************/
			LIB_FORCEINLINE bool is_repeated() const 
			{ return repeated_; }

		private:
			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			bool __start();

			/*********************************************************************************
			 * Set status
			 ********************************************************************************/
			LIB_FORCEINLINE bool __set_status(int32 o, int32 n) 
			{ return status_.compare_exchange_strong(o, n); }

		private:
			// Timer status
			std::atomic_int status_;
			// Timer callback
			timer_callback cb_;
			// Repeated status
			volatile bool repeated_;
			// Timeout interval with ms
			uint64 interval_;
			// Timeout time with ms
			uint64 overtime_;
		};
		DEFINE_ALL_POINTER_TYPE(timer);

	}
}

#endif
