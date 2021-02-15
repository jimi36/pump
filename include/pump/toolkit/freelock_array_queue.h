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

#ifndef pump_toolkit_freelock_array_queue_h
#define pump_toolkit_freelock_array_queue_h

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
    class LIB_PUMP freelock_array_queue
      : public noncopyable {

      public:
        // Element type
        typedef T element_type;
        // Element type size
        const static uint32_t element_size = sizeof(element_type);

        struct element_node {
            volatile int32_t ready;
            block_t data[element_size];
        };

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        freelock_array_queue(uint32_t size)
            : size_(0),
              size_mask_(0),
              nodes_(nullptr),
              write_index_(0),
              read_index_(0) {
            // Init array size.
            size_ = ceil_to_pow2(size);
            // Init array size mask.
            size_mask_ = size_ - 1;
            // Create element nodes.
            nodes_ = (element_node*)pump_malloc(size * sizeof(element_node));
            memset(nodes_, 0, size * sizeof(element_node));
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~freelock_array_queue() {
            if (nodes_) {
                int32_t beg = read_index_.load();
                int32_t end = write_index_.load();
                for (int32_t i = beg; i < end; i++) {
                    ((element_type*)nodes_[__count_to_index(i)].data)->~element_type();
                }
                pump_free(nodes_);
            }
        }

        /*********************************************************************************
         * Push
         ********************************************************************************/
        template <typename U>
        bool push(U &&data) {
            // Get current write index.
            int32_t cur_write_index = write_index_.load(std::memory_order_acquire);
            // Get max write index.
            int32_t max_write_index = read_index_.load(std::memory_order_relaxed);
            // Dest Element node.
            element_node *elem_node = nodes_ + __count_to_index(cur_write_index);

          try_again:
            // Check the node is ready status.
            while (elem_node->ready == 1) {
                // If the queue full just return.
                if (cur_write_index >= max_write_index) {
                    max_write_index = read_index_.load(std::memory_order_acquire);
                    if (cur_write_index >= max_write_index) {
                        return false;
                    }
                }
                cur_write_index = write_index_.load(std::memory_order_relaxed);
                elem_node = nodes_ + __count_to_index(cur_write_index);
            }

            if (!write_index_.compare_exchange_strong(cur_write_index,
                                                      cur_write_index + 1,
                                                      std::memory_order_acquire,
                                                      std::memory_order_relaxed)) {
                elem_node = nodes_ + __count_to_index(cur_write_index);
                goto try_again;
            }

            // Construct element data.
            new ((element_type*)elem_node->data) element_type(std::forward<U>(data));

            // Mark element node ready.
            elem_node->ready = 1;

            return true;
        }

        /*********************************************************************************
         * Pop
         ********************************************************************************/
        template <typename U>
        bool pop(U &data) {
            // Get current read index.
            int32_t cur_read_index = read_index_.load(std::memory_order_acquire);
            int32_t max_read_index = write_index_.load(std::memory_order_relaxed);
            // Dest element node
            element_node *elem_node = nodes_ + __count_to_index(cur_read_index);
            // Dest element
            element_type *elem = nullptr;

          try_again:
            // Check the node is ready status.
            while (elem_node->ready == 0) {
                if (cur_read_index == max_read_index) {
                    max_read_index = write_index_.load(std::memory_order_acquire);
                    if (cur_read_index == max_read_index) {
                        return false;
                    }
                }
                cur_read_index = read_index_.load(std::memory_order_relaxed);
                elem_node = nodes_ + __count_to_index(cur_read_index);
            }

            if (!read_index_.compare_exchange_strong(cur_read_index,
                                                     cur_read_index + 1,
                                                     std::memory_order_acquire,
                                                     std::memory_order_relaxed)) {
                elem_node = nodes_ + __count_to_index(cur_read_index);
                goto try_again;
            }

            // Pop element.
            elem = (element_type*)(elem_node->data);
            data = std::move(*elem);
            elem->~element_type();

            // Mark element not ready.
            elem_node->ready = 0;

            return true;
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
            return (count & size_mask_);
        }

      private:
        // Size
        int32_t size_;
        // Size mask
        int32_t size_mask_;

        // Element nodes
        element_node *nodes_;

        // Next write index
        std::atomic_int32_t write_index_;
        // Next read index
        std::atomic_int32_t read_index_;
    };

}  // namespace toolkit
}  // namespace pump

#endif