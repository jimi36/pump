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

#ifndef librabbit_utils_freelock_h
#define librabbit_utils_freelock_h

#include "librabbit/deps.h"

namespace librabbit {
	namespace utils {

		template <typename ELEM_T, uint32 Q_SIZE = 1024>
		class freelock_array
		{
		public:
			freelock_array() : write_index_(0), read_index_(0), max_read_index_(0)
			{
			}
			
			virtual ~freelock_array()
			{
			}

			/// @brief returns the current number of items in the queue
			/// It tries to take a snapshot of the size of the queue, but in busy environments
			/// this function might return bogus values. 
			///
			/// If a reliable queue size must be kept you might want to have a look at 
			/// the preprocessor variable in this header file called 'ARRAY_LOCK_FREE_Q_KEEP_REAL_SIZE'
			/// it enables a reliable size though it hits overall performance of the queue 
			/// (when the reliable size variable is on it's got an impact of about 20% in time)
			uint32 size()
			{
				uint32 cur_read_index = read_index_.load();
				uint32 cur_write_index = write_index_.load();

				if (cur_write_index >= cur_read_index)
				{
					return (cur_write_index - cur_read_index);
				}
				else
				{
					return (Q_SIZE + cur_write_index - cur_read_index);
				}
			}

			/// @brief push an element at the tail of the queue
			/// @param the element to insert in the queue
			/// Note that the element is not a pointer or a reference, so if you are using large data
			/// structures to be inserted in the queue you should think of instantiate the template
			/// of the queue as a pointer to that large structure
			/// @returns true if the element was inserted in the queue. False if the queue was full
			bool push(const ELEM_T &data)
			{
				uint32 cur_write_index = write_index_.load();
				do
				{
					// the queue is full
					if (count_to_index(cur_write_index + 1) == count_to_index(read_index_.load()))
						return false;

				} while (!write_index_.compare_exchange_strong(cur_write_index, cur_write_index + 1));
				//while (!thread::atomic_bool_cas(&write_index_, cur_write_index, (cur_write_index + 1)));

				array_[count_to_index(cur_write_index)] = data;

				uint32 cur_max_read_index = max_read_index_.load();
				while (!max_read_index_.compare_exchange_strong(cur_max_read_index, cur_max_read_index + 1));
				// while (!thread::atomic_bool_cas(&max_read_index_, cur_max_read_index, (cur_max_read_index + 1)));

				return true;
			}

			/// @brief pop the element at the head of the queue
			/// @param a reference where the element in the head of the queue will be saved to
			/// Note that the a_data parameter might contain rubbish if the function returns false
			/// @returns true if the element was successfully extracted from the queue. False if the queue was empty
			bool pop(ELEM_T &data)
			{
				uint32 cur_read_index = read_index_.load();
				do
				{
					// the queue is empty or
					// a producer thread has allocate space in the queue but is 
					// waiting to commit the data into it
					if (count_to_index(cur_read_index) == count_to_index(max_read_index_.load()))
						return false;

					data = array_[count_to_index(cur_read_index)];

					if (read_index_.compare_exchange_strong(cur_read_index, cur_read_index + 1))
					//if (thread::atomic_bool_cas(&read_index_, cur_read_index, (cur_read_index + 1)))
						return true;

				} while (1); // keep looping to try again!

				// Something went wrong. it shouldn't be possible to reach here
				assert(0);

				// Add this return statement to avoid compiler warnings
				return false;
			}

		private:
			/// @brief calculate the index in the circular array that corresponds
			/// to a particular "count" value
			inline uint32 count_to_index(uint32 count)
			{
				return (count % Q_SIZE);
			}

		private:
			/// @brief array to keep the elements
			ELEM_T array_[Q_SIZE];

			/// @brief where a new element will be inserted
			// volatile uint32 write_index_;
			std::atomic_uint32_t write_index_;

			/// @brief where the next element where be extracted from
			// volatile uint32 read_index_;
			std::atomic_uint32_t read_index_;

			/// @brief maximum read index for multiple producer queues
			/// If it's not the same as m_writeIndex it means
			/// there are writes pending to be "committed" to the queue, that means,
			/// the place for the data was reserved (the index in the array) but  
			/// data is still not in the queue, so the thread trying to read will have 
			/// to wait for those other threads to save the data into the queue
			///
			/// note this index is only used for MultipleProducerThread queues
			// volatile uint32 max_read_index_;
			std::atomic_uint32_t max_read_index_;
		};

	}
}

#endif
