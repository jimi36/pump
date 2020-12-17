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

#ifndef pump_toolkit_array_freelock_h
#define pump_toolkit_array_freelock_h

#include <atomic>
#include <chrono>

#include "pump/utils.h"
#include "pump/debug.h"
#include "pump/memory.h"
#include "pump/platform.h"
#include "pump/toolkit/features.h"
#include "pump/toolkit/semaphore.h"

namespace pump {
namespace toolkit {

    template <typename T>
    class LIB_PUMP array_freelock_queue
      : public noncopyable {

      public:
        // Element type
        typedef T element_type;
        // Element type size
        const static uint32_t element_size = sizeof(element_type);

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        array_freelock_queue(uint32_t size)
            : size_(0),
              mem_block_(nullptr),
              write_index_(0),
              max_write_index_(0),
              read_index_(0),
              max_read_index_(0) {
            // Init element size.
            size_ = ceil_to_pow2(size);
            // Init element size mask.
            element_size_mask_ = size_ - 1;
            // Create memory block.
            mem_block_ = (block_t*)pump_malloc(size * element_size);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~array_freelock_queue() {
            if (mem_block_) {
                int32_t read_index = read_index_.load();
                int32_t max_read_index = max_read_index_.load();
                while (__count_to_index(read_index) != __count_to_index(max_read_index)) {
                    ((element_type *)mem_block_ + __count_to_index(read_index++))
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
            int32_t cur_write_index = write_index_.load(std::memory_order_acquire);
            do {
                // Array is full
                if (__count_to_index(cur_write_index + 1) ==
                    __count_to_index(max_write_index_.load(std::memory_order_acquire))) {
                    return false;
                }

                if (write_index_.compare_exchange_strong(cur_write_index,
                                                         cur_write_index + 1,
                                                         std::memory_order_acquire,
                                                         std::memory_order_relaxed)) {
                    break;
                }
            } while (true);

            // Construct element object
            new ((element_type *)mem_block_ + __count_to_index(cur_write_index)) element_type(data);

            int32_t index = cur_write_index;
            while (!max_read_index_.compare_exchange_weak(index,
                                                          index + 1,
                                                          std::memory_order_release,
                                                          std::memory_order_relaxed)) {
                index = cur_write_index;
            }

            return true;
        }

        /*********************************************************************************
         * Pop
         * Return false if array is empty, thread safe.
         ********************************************************************************/
        template <typename U>
        bool pop(U &data) {
            int32_t cur_read_index = read_index_.load(std::memory_order_relaxed);
            do {
                int32_t array_read_index = __count_to_index(cur_read_index);
                if (array_read_index == __count_to_index(max_read_index_.load(std::memory_order_acquire))) {
                    return false;
                }

                if (read_index_.compare_exchange_strong(cur_read_index,
                                                        cur_read_index + 1,
                                                        std::memory_order_acquire,
                                                        std::memory_order_relaxed)) {
                    // Copy element.
                    element_type *elem = (element_type*)mem_block_ + array_read_index;
                    data = std::move(*elem);
                    // Deconstruct element.
                    elem->~element_type();

                    int32_t index = cur_read_index;
                    while (!max_write_index_.compare_exchange_weak(index,
                                                                   index + 1,
                                                                   std::memory_order_release,
                                                                   std::memory_order_relaxed)) {
                        index = cur_read_index;
                    }

                    return true;
                }
            } while (true);  // keep looping to try again!

            // Add this return statement to avoid compiler warnings
            return false;
        }

        /*********************************************************************************
         * Get size
         ********************************************************************************/
        PUMP_INLINE int32_t size() const {
            int32_t cur_read_index = read_index_.load(std::memory_order_relaxed);
            int32_t cur_write_index = write_index_.load(std::memory_order_relaxed);

            if (cur_write_index >= cur_read_index) {
                return (cur_write_index - cur_read_index);
            } else {
                return (size_ + cur_write_index - cur_read_index);
            }
        }

        /*********************************************************************************
         * Empty
         ********************************************************************************/
        PUMP_INLINE bool empty() const {
            return size() > 0;
        }

        /*********************************************************************************
         * Get capacity
         ********************************************************************************/
        PUMP_INLINE int32_t capacity() const {
            return size_;
        }

      private:
        /*********************************************************************************
         * Count to index
         ********************************************************************************/
        PUMP_INLINE int32_t __count_to_index(int32_t count) const {
            return (count & element_size_mask_);
        }

      private:
        // Capacity size
        int32_t size_;

        // Element memory block
        block_t *mem_block_;

        // Element size mask
        int32_t element_size_mask_;

        // Next write index
        std::atomic_int32_t write_index_;
        // Max write index
        // It should be equal or littel read index at all
        std::atomic_int32_t max_write_index_;

        // Next read index
        std::atomic_int32_t read_index_;
        // Max read index
        // It should be equal write index at all
        std::atomic_int32_t max_read_index_;
    };

}  // namespace toolkit
}  // namespace pump

#endif