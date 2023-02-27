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

#ifndef pump_toolkit_freelock_arr_queue_h
#define pump_toolkit_freelock_arr_queue_h

#include <atomic>
#include <chrono>

#include <pump/utils.h>
#include <pump/debug.h>
#include <pump/memory.h>
#include <pump/platform.h>
#include <pump/toolkit/features.h>
#include <pump/toolkit/semaphore.h>

namespace pump {
namespace toolkit {

/*********************************************************************************
 * The freelock_arr_queue is freelock queue implemented by fix size array,
 * and its use case is that many producers and many consumers push and pop
 * elements at the same time.
 ********************************************************************************/
template <typename T>
class freelock_arr_queue : public noncopyable {
  public:
    // Element type
    typedef T element_type;
    // Element type size
    const static uint32_t element_size = sizeof(element_type);
    // Element no constructor flag
    constexpr static bool no_constructor =
        std::is_integral<element_type>::value ||
        std::is_pointer<element_type>::value;

    struct element_node {
        element_node()
          : ready(0) {
        }

        volatile int32_t ready;

        char data[element_size];
    };

  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    freelock_arr_queue(uint32_t size)
      : size_(0),
        size_mask_(0),
        nodes_(nullptr),
        read_index_(0),
        write_index_(1) {
        // Init array size.
        size_ = ceil_to_power_of_two(size);
        // Init array size mask.
        size_mask_ = size_ - 1;
        // Create element nodes.
        nodes_ = (element_node *)pump_malloc(size * sizeof(element_node));
        if (nodes_ == nullptr) {
            pump_abort();
        }
        memset(nodes_, 0, size * sizeof(element_node));
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~freelock_arr_queue() {
        if (nodes_) {
            auto beg = read_index_.load();
            auto end = write_index_.load();
            for (auto i = beg; i < end; i++) {
                auto idx = __count_to_index(i);
                ((element_type *)nodes_[idx].data)->~element_type();
            }
            pump_free(nodes_);
        }
    }

    /*********************************************************************************
     * Push
     ********************************************************************************/
    template <typename U>
    bool push(U &&data) {
        // Current write index.
        auto cur_write_index = write_index_.load(std::memory_order_relaxed);
        // Max write index.
        auto max_write_index = read_index_.load(std::memory_order_relaxed);

        do {
            // If the queue full just return.
            if (cur_write_index == max_write_index) {
                max_write_index = read_index_.load(std::memory_order_acquire);
                if (cur_write_index == max_write_index) {
                    return false;
                }
            }

            if (write_index_.compare_exchange_strong(
                    cur_write_index,
                    cur_write_index + 1,
                    std::memory_order_acquire,
                    std::memory_order_relaxed)) {
                break;
            }
        } while (true);

        // Check the node is ready status.
        auto elem_node = nodes_ + __count_to_index(cur_write_index);
        while (elem_node->ready == 1) {
        }

        // Construct node data.
        if (no_constructor) {
            *(element_type *)(elem_node->data) = data;
        } else {
            new ((element_type *)elem_node->data) element_type(std::forward<U>(data));
        }

        // Mark element node ready.
        elem_node->ready = 1;

        return true;
    }

    /*********************************************************************************
     * Pop
     ********************************************************************************/
    template <typename U>
    bool pop(U &data) {
        // Current read index.
        auto cur_read_index = read_index_.load(std::memory_order_relaxed);
        // Current read index.
        auto max_read_index = write_index_.load(std::memory_order_relaxed);

        do {
            if (cur_read_index + 1 == max_read_index) {
                max_read_index = write_index_.load(std::memory_order_acquire);
                if (cur_read_index + 1 == max_read_index) {
                    return false;
                }
            }

            if (read_index_.compare_exchange_strong(
                    cur_read_index,
                    cur_read_index + 1,
                    std::memory_order_acquire,
                    std::memory_order_relaxed)) {
                break;
            }
        } while (true);

        // Check the node is ready status.
        auto elem_node = nodes_ + __count_to_index(cur_read_index + 1);
        while (elem_node->ready == 0) {
        }

        // Pop element data.
        if (no_constructor) {
            data = *(element_type *)(elem_node->data);
        } else {
            auto elem = (element_type *)(elem_node->data);
            data = std::move(*elem);
            elem->~element_type();
        }

        // Mark element not ready.
        elem_node->ready = 0;

        return true;
    }

    /*********************************************************************************
     * Get size
     ********************************************************************************/
    pump_inline int32_t size() const noexcept {
        auto cur_read_index = read_index_.load(std::memory_order_relaxed);
        auto cur_write_index = write_index_.load(std::memory_order_relaxed);

        if (cur_write_index >= cur_read_index) {
            return (cur_write_index - cur_read_index);
        } else {
            return (size_ + cur_write_index - cur_read_index);
        }
    }

    /*********************************************************************************
     * Empty
     ********************************************************************************/
    pump_inline bool empty() const noexcept {
        return size() > 0;
    }

    /*********************************************************************************
     * Get capacity
     ********************************************************************************/
    pump_inline int32_t capacity() const noexcept {
        return size_;
    }

  private:
    /*********************************************************************************
     * Count to index
     ********************************************************************************/
    pump_inline int32_t __count_to_index(int32_t count) const noexcept {
        return (count & size_mask_);
    }

  private:
    // Size
    int32_t size_;
    // Size mask
    int32_t size_mask_;

    // Element nodes
    pump_cache_line_alignas element_node *nodes_;

    // Next read index
    pump_cache_line_alignas std::atomic_int32_t read_index_;
    // Next write index
    pump_cache_line_alignas std::atomic_int32_t write_index_;
};

}  // namespace toolkit
}  // namespace pump

#endif
