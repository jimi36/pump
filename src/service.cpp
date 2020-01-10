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
		iocp_poller_(nullptr),
		waiting_for_task_(true)
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
			tqueue_->start(function::bind(&service::__post_pending_timer, this, _1));

		if (iocp_poller_ != nullptr)
			iocp_poller_->start();

		if (loop_poller_ != nullptr)
			loop_poller_->start();

		if (once_poller_ != nullptr)
			once_poller_->start();

		task_worker_.reset(
			new std::thread([&]() {
				while (running_)
					__do_posted_tasks();
			}
		));

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

	void service::wait_stop()
	{
		if (iocp_poller_)
			iocp_poller_->wait_stop();

		if (loop_poller_)
			loop_poller_->wait_stop();

		if (once_poller_)
			once_poller_->wait_stop();

		if (task_worker_)
			task_worker_->join();
	}

	bool service::add_channel_tracker(poll::channel_tracker_sptr &tracker)
	{
#if defined(WIN32) && defined(USE_IOCP)
		poll::poller_ptr poller = iocp_poller_;
#else
		poll::poller_ptr poller = nullptr;
		if (tracker->get_track_mode() == TRACK_MODE_KEPPING)
			poller = loop_poller_;
		else
			poller = once_poller_;
#endif
		if (poller == nullptr)
			return false;

		poller->add_channel_tracker(tracker);

		return true;
	}

	bool service::awake_channel_tracker(poll::channel_tracker_sptr &tracker)
	{
#if defined(WIN32) && defined(USE_IOCP)
		poll::poller_ptr poller = iocp_poller_;
#else
		poll::poller_ptr poller = nullptr;
		if (tracker->get_track_mode() == TRACK_MODE_KEPPING)
			poller = loop_poller_;
		else
			poller = once_poller_;
#endif
		if (poller == nullptr)
			return false;

		poller->awake_channel_tracker(tracker);

		return true;
	}

	bool service::remove_channel_tracker(poll::channel_tracker_sptr &tracker)
	{
#if defined(WIN32) && defined(USE_IOCP)
		poll::poller_ptr poller = iocp_poller_;
#else
		poll::poller_ptr poller = nullptr;
		if (tracker->get_track_mode() == TRACK_MODE_KEPPING)
			poller = loop_poller_;
		else
			poller = once_poller_;
#endif
		if (poller == nullptr)
			return false;

		poller->remove_channel_tracker(tracker);

		return true;
	}

	bool service::post_channel_event(poll::channel_sptr &ch, uint32 event)
	{
#if defined(WIN32) && defined(USE_IOCP)
		poll::poller_ptr poller = iocp_poller_;
#else
		poll::poller_ptr poller = once_poller_;
#endif
		if (poller == nullptr)
			return false;

		poller->push_channel_event(ch, event);

		return true;
	}

	void service::post(const post_task_type& task)
	{
		std::unique_lock<std::mutex> locker(task_mx_);
		tasks_.push_back(task);

		if (waiting_for_task_)
			task_cv_.notify_all();
	}

	bool service::start_timer(time::timer_sptr &tr)
	{
		time::timer_queue_ptr tq = tqueue_.get();
		if (tq == nullptr)
			return false;
		if (!tr->start())
			return false;
		tq->add_timer(tr);
		return true;
	}

	void service::stop_timer(time::timer_sptr &tr)
	{
		if (tr)
			tr->stop();
	}

	net::iocp_handler service::get_iocp_handler() const
	{
		if (iocp_poller_ == nullptr)
			return nullptr;

		poll::iocp_poller_ptr poller = (poll::iocp_poller_ptr)iocp_poller_;
		return poller->get_iocp_handler();
	}

	void service::__post_pending_timer(time::timer_wptr &tr)
	{
		std::unique_lock<std::mutex> locker(task_mx_);
		timers_.push_back(tr);

		if (waiting_for_task_)
			task_cv_.notify_all();
	}

	void service::__do_posted_tasks()
	{
		std::vector<time::timer_wptr> process_timers;
		std::vector<post_task_type> process_tasks;
		{
			std::unique_lock<std::mutex> locker(task_mx_);
			if (tasks_.empty() && timers_.empty())
			{
				waiting_for_task_ = true;
				task_cv_.wait_for(locker, std::chrono::seconds(1));
				waiting_for_task_ = false;
			}

			if (!tasks_.empty())
				process_tasks.swap(tasks_);
			if (!timers_.empty())
				process_timers.swap(timers_);
		}

		for (int32 i = 0; i < (int32)process_tasks.size(); ++i)
		{
			if (process_tasks[i])
				process_tasks[i]();
		}

		for (int32 i = 0; i < (int32)process_timers.size(); ++i)
		{
			time::timer_sptr tr_locker = process_timers[i].lock();
			time::timer_ptr tr = tr_locker.get();
			if (tr)
			{
				tr->handle_timeout();
				if (tr->is_repeated() && tr->start())
					tqueue_->add_timer(tr_locker);
			}
		}
	}

}
