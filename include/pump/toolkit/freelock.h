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

#ifndef pump_toolkit_freelock_h
#define pump_toolkit_freelock_h

#include <atomic>
#include <chrono>

#include "pump/types.h"
#include "pump/debug.h"
#include "pump/memory.h"
#include "pump/platform.h"
#include "pump/toolkit/semaphore.h"

namespace pump {
namespace toolkit {

    template <typename T>
    class freelock_array {
      protected:
        // Element type
        typedef T element_type;
        // Element type size
        const static uint32 element_size = sizeof(element_type);

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        freelock_array(uint32 size)
            : size_(size),
              mem_block_(nullptr),
              write_index_(0),
              max_write_index_(0),
              read_index_(0),
              max_read_index_(0) {
            mem_block_ = (block_ptr)pump_malloc(size * element_size);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~freelock_array() {
            if (mem_block_) {
                uint32 read_index = read_index_.load();
                uint32 max_read_index = max_read_index_.load();
                while (count_to_index(read_index) != count_to_index(max_read_index)) {
                    ((element_type *)mem_block_ + count_to_index(read_index++))
                        ->~element_type();
                }
                pump_free(mem_block_);
            }
        }

        /*********************************************************************************
         * Push
         * Return false if array is full, thread safe.
         ********************************************************************************/
        bool push(const element_type &data) {
            uint32 cur_write_index = write_index_.load(std::memory_order_relaxed);
            do {
                // Array is full
                if (count_to_index(cur_write_index + 1) ==
                    count_to_index(max_write_index_.load(std::memory_order_acquire))) {
                    return false;
                }

                if (write_index_.compare_exchange_strong(cur_write_index,
                                                         cur_write_index + 1,
                                                         std::memory_order_acquire,
                                                         std::memory_order_relaxed)) {
                    break;
                }
                cur_write_index = write_index_.load(std::memory_order_relaxed);

                std::atomic_signal_fence(std::memory_order_acquire);
            } while (1);

            // New element object
            new ((element_type *)mem_block_ + count_to_index(cur_write_index))
                element_type(data);

            while (!max_read_index_.compare_exchange_strong(cur_write_index,
                                                            cur_write_index + 1,
                                                            std::memory_order_relaxed,
                                                            std::memory_order_relaxed)) {
            }

            return true;
        }

        /*********************************************************************************
         * Pop
         * Return false if array is empty, thread safe.
         ********************************************************************************/
        template <typename U>
        bool pop(U &data) {
            do {
                uint32 cur_read_index = read_index_.load(std::memory_order_relaxed);
                if (count_to_index(cur_read_index) ==
                    count_to_index(max_read_index_.load(std::memory_order_acquire))) {
                    return false;
                }

                if (read_index_.compare_exchange_strong(cur_read_index,
                                                        cur_read_index + 1,
                                                        std::memory_order_acquire,
                                                        std::memory_order_relaxed)) {
                    // Copy element object
                    data = *((element_type *)mem_block_ + count_to_index(cur_read_index));
                    // Deconstructor old element object
                    ((element_type *)mem_block_ + count_to_index(cur_read_index))
                        ->~element_type();

                    while (!max_write_index_.compare_exchange_strong(
                        cur_read_index,
                        cur_read_index + 1,
                        std::memory_order_relaxed,
                        std::memory_order_relaxed)) {
                    }

                    return true;
                }

                std::atomic_signal_fence(std::memory_order_acquire);
            } while (1);  // keep looping to try again!

            // Something went wrong. it shouldn't be possible to reach here
            PUMP_ASSERT(0);

            // Add this return statement to avoid compiler warnings
            return false;
        }

        /*********************************************************************************
         * Get array data size
         ********************************************************************************/
        uint32 size() {
            uint32 cur_read_index = read_index_.load(std::memory_order_relaxed);
            uint32 cur_write_index = write_index_.load(std::memory_order_relaxed);

            if (cur_write_index >= cur_read_index) {
                return (cur_write_index - cur_read_index);
            } else {
                return (size_ + cur_write_index - cur_read_index);
            }
        }

        /*********************************************************************************
         * Get array capacity
         ********************************************************************************/
        uint32 capacity() {
            return size_;
        }

      private:
        /*********************************************************************************
         * Map count to index
         ********************************************************************************/
        PUMP_INLINE uint32 count_to_index(uint32 count) {
            return (count % size_);
        }

      private:
        // Capacity size
        uint32 size_;

        // Element memory block
        block_ptr mem_block_;

        // Next write index
        std::atomic_uint32_t write_index_;

        // Max write index
        // It should be equal or littel read index at all
        std::atomic_uint32_t max_write_index_;

        // Next read index
        std::atomic_uint32_t read_index_;

        // Max read index
        // It should be equal write index at all
        std::atomic_uint32_t max_read_index_;
    };

    template <typename T>
    class freelock_list {
      protected:
        // Array element type
        typedef T array_element_type;
        // Freelock array type
        typedef freelock_array<array_element_type> freelock_array_type;

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        freelock_list(uint32 size)
            : array_(nullptr), resize_locker_(false), concurrent_cnt_(0) {
            array_ = new freelock_array_type(size);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~freelock_list() {
            if (array_) {
                delete array_;
            }
        }

        /*********************************************************************************
         * Push
         * It will new a bigger array if current array is full. So this function always
         * return true, thread safe.
         ********************************************************************************/
        bool push(const array_element_type &data) {
            while (true) {
                // check resize locker locked state and wait it free
                if (resize_locker_.load(std::memory_order_acquire)) {
                    continue;
                }

                // add concurrent count
                concurrent_cnt_.fetch_add(1, std::memory_order_release);

                // recheck resize locker locked state
                if (resize_locker_.load(std::memory_order_relaxed)) {
                    // sub concurrent count if resize locker locked
                    concurrent_cnt_.fetch_sub(1, std::memory_order_release);
                    // try again for next time
                    continue;
                }

                // push data to array
                // failed if array is full, and try to resize array
                if (!array_->push(data)) {
                    // try to get array resize locker
                    bool unlocked = false;
                    if (resize_locker_.compare_exchange_strong(
                            unlocked,
                            true,
                            std::memory_order_acquire,
                            std::memory_order_relaxed)) {
                        // wait other concurrent caller handle array finished
                        while (concurrent_cnt_.load(std::memory_order_relaxed) != 1)
                            ;

                        // new bigger array
                        __new_bigger_array();

                        // push datat to array again
                        PUMP_DEBUG_CHECK(array_->push(data));

                        // resize locker unlock
                        resize_locker_.store(false, std::memory_order_release);

                        break;
                    }

                    // sub concurrent count if getting array resize locker failed
                    concurrent_cnt_.fetch_sub(1, std::memory_order_release);

                    // try to push data again
                    continue;
                }

                break;
            }

            // push finished and sub concurrent count
            concurrent_cnt_.fetch_sub(1, std::memory_order_release);

            return true;
        }

        /*********************************************************************************
         * Pop
         * Return false if array is empty, thread safe.
         ********************************************************************************/
        template <typename U>
        bool pop(U &data) {
            bool ret = false;
            while (true) {
                // check resize locker locked state and wait it free
                if (resize_locker_.load(std::memory_order_acquire)) {
                    continue;
                }

                // add concurrent count
                concurrent_cnt_.fetch_add(1, std::memory_order_release);

                // recheck resize locker locked state
                if (resize_locker_.load(std::memory_order_relaxed)) {
                    // sub concurrent count if resize locker locked
                    concurrent_cnt_.fetch_sub(1, std::memory_order_release);
                    // try again for next time
                    continue;
                }

                // pop data from array
                ret = array_->pop(data);

                // push finished and sub concurrent count
                concurrent_cnt_.fetch_sub(1, std::memory_order_release);

                break;
            }

            return ret;
        }

      private:
        /*********************************************************************************
         * New bigger array
         * Return false if array is empty, thread safe.
         ********************************************************************************/
        void __new_bigger_array() {
            uint32 capacity = array_->capacity();
            if (capacity < 1024) {
                capacity *= 2;
            } else {
                capacity += 1024;
            }
            freelock_array_type *new_array = new freelock_array_type(capacity);

            array_element_type data;
            while (array_->pop(data)) {
                new_array->push(data);
            }

            delete array_;

            array_ = new_array;
        }

      private:
        // Freelock array
        freelock_array_type *array_;

        // Array resize locker
        std::atomic_bool resize_locker_;

        // Concurrent count
        std::atomic_uint32_t concurrent_cnt_;
    };

    template <typename T>
    class block_freelock_queue {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        block_freelock_queue(uint32 init_size = 1024) : list_(init_size) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~block_freelock_queue() {
        }

        /*********************************************************************************
         * Enqueue
         ********************************************************************************/
        bool enqueue(const T &item) {
            if (PUMP_LIKELY(list_.push(item))) {
                semaphone_.signal();
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Enqueue
         ********************************************************************************/
        bool enqueue(T &&item) {
            if (PUMP_LIKELY(list_.push(item))) {
                semaphone_.signal();
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Dequeue
         * This will block until dequeue success.
         ********************************************************************************/
        template <typename U>
        bool dequeue(U &item) {
            if (semaphone_.wait()) {
                while (!list_.pop(item)) {
                    continue;
                }
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Dequeue
         * This will block until dequeue success or timeout.
         ********************************************************************************/
        template <typename U>
        bool dequeue(U &item, uint64 timeout) {
            if (semaphone_.wait(timeout)) {
                while (!list_.pop(item)) {
                    continue;
                }
                return true;
            }
            return false;
        }

        template <typename U, typename Rep, typename Period>
        bool dequeue(U &item, std::chrono::duration<Rep, Period> const &timeout) {
            if (semaphone_.wait(
                    std::chrono::duration_cast<std::chrono::microseconds>(timeout)
                        .count())) {
                while (!list_.pop(item)) {
                    continue;
                }
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Try dequeue
         * This will return immediately.
         ********************************************************************************/
        template <typename U>
        bool try_dequeue(U &item) {
            if (semaphone_.try_wait()) {
                while (!list_.pop(item)) {
                    continue;
                }
                return true;
            }
            return false;
        }

      private:
        freelock_list<T> list_;
        light_semaphore semaphone_;
    };

}  // namespace toolkit
}  // namespace pump

#endif