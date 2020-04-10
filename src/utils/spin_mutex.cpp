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

#include "pump/utils/spin_mutex.h"

namespace pump {
	namespace utils {

		spin_mutex::spin_mutex(int32 per_loop) :
			per_loop_(per_loop)
		{
			unlock();
		}

		spin_mutex::~spin_mutex()
		{
		}

		void spin_mutex::lock()
		{
			int32 loop = 0;

			while (1)
			{
				if (!locked_.test_and_set())
					break;

				loop++;

				if (loop >= per_loop_)
				{
					loop = 0;
#ifdef WIN32
					SwitchToThread();
#else
					sched_yield();
#endif
				}
			}
		}

	}
}