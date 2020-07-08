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

#include "pump/time/timestamp.h"
#include "pump/toolkit/features.h"

namespace pump {
	namespace time {

		class timer;
		DEFINE_ALL_POINTER_TYPE(timer);

		class timer_queue;
		DEFINE_ALL_POINTER_TYPE(timer_queue);

		typedef pump_function<void()> timer_callback;

		class LIB_PUMP timer : 
			public std::enable_shared_from_this<timer>
		{
		protected:
			friend class timer_queue;

		public:
			/*********************************************************************************
			 * Create instance
			 ********************************************************************************/
			PUMP_INLINE static timer_sptr create_instance(
				uint64 timeout, 
				const timer_callback &cb,
				bool repeated = false
			) {
				INLINE_OBJECT_CREATE(
					obj, 
					timer, 
					(timeout, cb, repeated)
				);
				return timer_sptr(obj, object_delete<timer>);
			}

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
			void handle_timeout();

			/*********************************************************************************
			 * Get overtime
			 ********************************************************************************/
			PUMP_INLINE uint64 time() const
			{ return overtime_; }

			/*********************************************************************************
			 * Get starting state
			 ********************************************************************************/
			PUMP_INLINE bool is_started() const
			{ return status_.load() >= 2; }

			/*********************************************************************************
			 * Get repeated status
			 ********************************************************************************/
			PUMP_INLINE bool is_repeated() const
			{ return repeated_; }

		private:
			/*********************************************************************************
			 * Constructor
			 ********************************************************************************/
			timer(uint64 timeout, const timer_callback &cb, bool repeated) noexcept;

			/*********************************************************************************
			 * Start
			 ********************************************************************************/
			bool __start(timer_queue_ptr queue);

			/*********************************************************************************
			 * Restart
			 ********************************************************************************/
			bool __restart();

			/*********************************************************************************
			 * Set status
			 ********************************************************************************/
			PUMP_INLINE bool __set_status(int32 o, int32 n)
			{ return status_.compare_exchange_strong(o, n); }

		private:
			// Timer queue
			timer_queue_ptr queue_;
			// Timer status
			std::atomic_int status_;
			// Timer callback
			timer_callback cb_;
			// Repeated status
			bool repeated_;
			// Timeout with ms
			uint64 timeout_;
			// Timeout time with ms
			uint64 overtime_;
		};

	}
}

#endif
