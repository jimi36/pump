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

#ifndef pump_service_h
#define pump_service_h

#include "pump/net/iocp.h"
#include "pump/poll/poller.h"
#include "pump/time/timer_queue.h"
#include "pump/utils/features.h"

namespace pump {

	class LIB_EXPORT service: 
		public utils::noncopyable
	{
	protected:
		typedef function::function<void()> post_task_type;
		
	public:
		/*********************************************************************************
		 * Constructor
		 ********************************************************************************/
		service(bool enable_poller = true);

		/*********************************************************************************
		 * Deconstructor
		 ********************************************************************************/
		~service();

		/*********************************************************************************
		 * Start
		 ********************************************************************************/
		bool start();

		/*********************************************************************************
		 * Stop
		 ********************************************************************************/
		void stop();

		/*********************************************************************************
		 * Wait stopping
		 ********************************************************************************/
		void wait_stopped();

		/*********************************************************************************
		 * Add channel checker
		 ********************************************************************************/
		bool add_channel_tracker(poll::channel_tracker_sptr &tracker);

		/*********************************************************************************
		 * Delete channel
		 ********************************************************************************/
		bool remove_channel_tracker(poll::channel_tracker_sptr &tracker);

		/*********************************************************************************
		 * Pause channel
		 ********************************************************************************/
		bool pause_channel_tracker(poll::channel_tracker_ptr tracker);

		/*********************************************************************************
		 * Awake channel
		 ********************************************************************************/
		bool awake_channel_tracker(poll::channel_tracker_ptr tracker);

		/*********************************************************************************
		 * Post channel event
		 ********************************************************************************/
		bool post_channel_event(poll::channel_sptr &ch, uint32 event);

		/*********************************************************************************
		 * Post callback task
		 ********************************************************************************/
		void post(const post_task_type &task);

		/*********************************************************************************
		 * Start timer
		 ********************************************************************************/
		bool start_timer(time::timer_sptr &tr);

		/*********************************************************************************
		 * Stop timer
		 ********************************************************************************/
		void stop_timer(time::timer_sptr &tr);

	private:
		/*********************************************************************************
		 * Post pending timer
		 ********************************************************************************/
		void __post_pending_timer(time::timer_wptr &tr);

		/*********************************************************************************
		 * Do posted task
		 ********************************************************************************/
		void __do_posted_tasks();

	private:
		// Running status
		bool running_;
		// Loop poller
		poll::poller_ptr loop_poller_;
		// Once poller
		poll::poller_ptr once_poller_;
		// IOCP poller
		poll::poller_ptr iocp_poller_;
		// Timer queue
		time::timer_queue_sptr tqueue_;
		// Callback task worker
		std::shared_ptr<std::thread> task_worker_;
		//  Callback tasks
		bool waiting_for_task_;
		std::mutex task_mx_;
		std::condition_variable task_cv_;
		std::vector<post_task_type> tasks_;
		std::vector<time::timer_wptr> timers_;
	};
	DEFINE_ALL_POINTER_TYPE(service);

	class LIB_EXPORT service_getter : public utils::noncopyable
	{
	public:
		/*********************************************************************************
		 * Constructor
		 ********************************************************************************/
		service_getter(service_ptr sv) : service_(sv)
		{
		}

		/*********************************************************************************
		 * Deconstructor
		 ********************************************************************************/
		virtual ~service_getter()
		{
		}

		/*********************************************************************************
		 * Get service
		 ********************************************************************************/
		service_ptr get_service()
		{
			return service_;
		}

	protected:
		/*********************************************************************************
		 * Set service
		 ********************************************************************************/
		void __set_service(service_ptr sv)
		{
			service_ = sv;
		}

	private:
		service_ptr service_;
	};

}

#endif
