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

#include "pump/service.h"
#include "pump/time/timer_queue.h"
#include "pump/poll/iocp_poller.h"
#include "pump/poll/epoll_poller.h"
#include "pump/poll/select_poller.h"

namespace pump {

	service::service(bool has_poller) :
		running_(false),
		loop_poller_(nullptr),
		once_poller_(nullptr),
		iocp_poller_(nullptr)
	{
		if (has_poller)
		{
#if defined(WIN32) && defined(USE_IOCP)
			iocp_poller_ = new poll::iocp_poller(false);
#else
#	ifdef WIN32
			loop_poller_ = new poll::select_poller(false);
			once_poller_ = new poll::select_poller(true);
#	else
			loop_poller_ = new poll::epoll_poller(false);
			once_poller_ = new poll::epoll_poller(true);
#	endif
#endif
		}

		tqueue_.reset(new time::timer_queue());
	}

	service::~service()
	{
		if (loop_poller_)
			delete loop_poller_;
		if (once_poller_)
			delete once_poller_;
		if (iocp_poller_)
			delete iocp_poller_;
	}

	bool service::start()
	{
		if (running_)
			return false;

		running_ = true;

		if (tqueue_ != nullptr)
			tqueue_->start(function::bind(&service::__post_timeout_timer, this, _1));
		if (iocp_poller_ != nullptr)
			iocp_poller_->start();
		if (loop_poller_ != nullptr)
			loop_poller_->start();
		if (once_poller_ != nullptr)
			once_poller_->start();

		__start_posted_task_worker();

		__start_timeout_timer_worker();

		return true;
	}

	void service::stop()
	{
		running_ = false;

		if (tqueue_)
			tqueue_->stop();
		if (iocp_poller_)
			iocp_poller_->stop();
		if (loop_poller_)
			loop_poller_->stop();
		if (once_poller_)
			once_poller_->stop();
	}

	void service::wait_stopped()
	{
		if (iocp_poller_)
			iocp_poller_->wait_stopped();
		if (loop_poller_)
			loop_poller_->wait_stopped();
		if (once_poller_)
			once_poller_->wait_stopped();
		if (tqueue_)
			tqueue_->wait_stopped();
		if (posted_task_worker_)
			posted_task_worker_->join();
		if (timeout_timer_worker_)
			timeout_timer_worker_->join();
	}

	bool service::add_channel_tracker(poll::channel_tracker_sptr &tracker, bool tracking)
	{
#if defined(WIN32) && defined(USE_IOCP)
		poll::poller_ptr poller = iocp_poller_;
#else
		poll::poller_ptr poller = nullptr;
		if (tracker->get_mode() == TRACK_MODE_LOOP)
			poller = loop_poller_;
		else
			poller = once_poller_;
#endif
		PUMP_ASSERT(poller);
		return poller->add_channel_tracker(tracker, tracking);
	}

	bool service::remove_channel_tracker(poll::channel_tracker_sptr &tracker)
	{
#if defined(WIN32) && defined(USE_IOCP)
		poll::poller_ptr poller = iocp_poller_;
#else
		poll::poller_ptr poller = nullptr;
		if (tracker->get_mode() == TRACK_MODE_LOOP)
			poller = loop_poller_;
		else
			poller = once_poller_;
#endif
		PUMP_ASSERT(poller);
		poller->remove_channel_tracker(tracker);

		return true;
	}

	bool service::pause_channel_tracker(poll::channel_tracker_ptr tracker)
	{
#ifndef USE_IOCP
		poll::poller_ptr poller = nullptr;
		if (tracker->get_mode() == TRACK_MODE_LOOP)
			poller = loop_poller_;
		else
			poller = once_poller_;

		PUMP_ASSERT(poller);
		poller->pause_channel_tracker(tracker);
#endif
		return true;
	}

	bool service::awake_channel_tracker(poll::channel_tracker_ptr tracker)
	{
#ifndef USE_IOCP
		poll::poller_ptr poller = nullptr;
		if (tracker->get_mode() == TRACK_MODE_LOOP)
			poller = loop_poller_;
		else
			poller = once_poller_;

		PUMP_ASSERT(poller);
		poller->awake_channel_tracker(tracker);
#endif
		return true;
	}

	bool service::post_channel_event(poll::channel_sptr &ch, uint32 event)
	{
#if defined(WIN32) && defined(USE_IOCP)
		poll::poller_ptr poller = iocp_poller_;
#else
		poll::poller_ptr poller = once_poller_;
#endif
		PUMP_ASSERT(poller);
		poller->push_channel_event(ch, event);

		return true;
	}

	bool service::start_timer(time::timer_sptr &tr)
	{
		PUMP_ASSERT_EXPR(tqueue_, 
			return tqueue_->add_timer(tr));
	}

	void service::stop_timer(time::timer_sptr &tr)
	{
		if (tr)
			tr->stop();
	}

	void service::__start_posted_task_worker()
	{
		posted_task_worker_.reset(new std::thread([&]() {
			while (running_)
			{
				post_task_type task;
				if (posted_tasks_.wait_dequeue_timed(task, std::chrono::seconds(1)))
					task();
			}
		}));
	}

	void service::__start_timeout_timer_worker()
	{
		timeout_timer_worker_.reset(new std::thread([&]() {
			while (running_)
			{
				time::timer_wptr wptr;
				if (timeout_timers_.wait_dequeue_timed(wptr, std::chrono::seconds(1)))
				{
					PUMP_LOCK_WPOINTER_EXPR(timer, wptr, true,
						timer->handle_timeout());
				}
			}
		}));
	}

}
