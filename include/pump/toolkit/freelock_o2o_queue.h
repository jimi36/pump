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

#ifndef pump_toolkit_freelock_o2o_queue_h
#define pump_toolkit_freelock_o2o_queue_h

#include <atomic>
#include <chrono>

#include <pump/utils.h>
#include <pump/debug.h>
#include <pump/toolkit/features.h>

namespace pump {
namespace toolkit {

/*********************************************************************************
 * The freelock_o2o_queue is freelock queue, and its use case is that one
 * producer and one consumer push and pop elements at the same time.
 ********************************************************************************/
template <typename T, int32_t PerBlockElementCount = 1024>
class freelock_o2o_queue : public noncopyable {
  public:
    // Element type
    typedef T element_type;
    // Element size
    constexpr static int32_t element_size = sizeof(element_type);
    // Element no constructor flag
    constexpr static bool no_constructor =
        std::is_integral<element_type>::value ||
        std::is_pointer<element_type>::value;

    // Block node
    struct block_node {
        block_node()
          : next(nullptr),
            head(0),
            cache_tail(0),
            tail(0),
            cache_head(0),
            data(nullptr) {
        }

        block_node *next;

        pump_cache_line_alignas std::atomic_int32_t head;
        int32_t cache_tail;

        pump_cache_line_alignas std::atomic_int32_t tail;
        int32_t cache_head;

        char *data;
    };

  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    freelock_o2o_queue(int32_t size)
      : capacity_(0),
        block_element_size_(PerBlockElementCount),
        blk_head_(nullptr),
        blk_tail_(nullptr) {
        // Init block element size.
        block_element_size_ = ceil_to_power_of_two(block_element_size_);
        // Init block element size mask.
        block_element_size_mask_ = block_element_size_ - 1;
        // Calculate init block count.
        int32_t blk_count = size / (block_element_size_ + 1) + 1;
        // Init list
        __init_list(blk_count);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~freelock_o2o_queue() {
        // Get head block node.
        auto head_blk = blk_head_.load(std::memory_order_relaxed);
        // Get tail block node.
        auto tail_blk = blk_tail_.load(std::memory_order_relaxed);

        do {
            if (!no_constructor) {
                // Get head and tail element position
                auto head = head_blk->head.load(std::memory_order_relaxed);
                auto tail = head_blk->tail.load(std::memory_order_relaxed);

                while (head != tail) {
                    // Destory element
                    auto elem = (element_type *)(head_blk->data + head * element_size);
                    elem->~element_type();
                    // Move next element position
                    head = (head + 1) & block_element_size_mask_;
                }
            }

            // Next block pointer.
            auto next_blk = head_blk->next;

            // Free block.
            pump_free(head_blk->data);
            pump_object_destroy(head_blk);

            // Move to next node.
            head_blk = next_blk;

        } while (head_blk != tail_blk);
    }

    /*********************************************************************************
     * Push
     ********************************************************************************/
    template <typename U>
    bool push(U &&data) {
        // Get tail block node
        auto blk = blk_tail_.load(std::memory_order_relaxed);
        // Get tail element position
        auto tail = blk->tail.load(std::memory_order_relaxed);
        // Get next tail element position
        auto next_tail = (tail + 1) & block_element_size_mask_;

        if (next_tail != blk->cache_head ||
            next_tail != (blk->cache_head = blk->head.load(std::memory_order_relaxed))) {
            std::atomic_thread_fence(std::memory_order_acquire);

            // Construct element
            if (no_constructor) {
                *(element_type *)(blk->data + tail * element_size) = data;
            } else {
                new (blk->data + tail * element_size) element_type(std::forward<U>(data));
            }

            std::atomic_thread_fence(std::memory_order_release);
            // Move tail position of block
            blk->tail.store(next_tail, std::memory_order_relaxed);
        } else if (blk->next != blk_head_.load(std::memory_order_relaxed)) {
            std::atomic_thread_fence(std::memory_order_acquire);

            // Get next block node
            blk = blk->next;

            // Update cache head element position and get tail element position
            tail = blk->cache_head = blk->head.load(std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_acquire);

            // Construct element
            if (no_constructor) {
                *(element_type *)(blk->data + tail * element_size) = data;
            } else {
                new (blk->data + tail * element_size) element_type(std::forward<U>(data));
            }

            // Get next tail element position
            next_tail = (tail + 1) & block_element_size_mask_;

            std::atomic_thread_fence(std::memory_order_release);
            // Move tail position of block
            blk->tail.store(next_tail, std::memory_order_relaxed);
            // Move tail block node
            blk_tail_.store(blk, std::memory_order_relaxed);
        } else {
            // Create new block node
            auto new_blk = pump_object_create<block_node>();
            if (new_blk == nullptr) {
                return false;
            }
            new_blk->data = (char *)pump_malloc(block_element_size_ * element_size);
            if (new_blk->data == nullptr) {
                return false;
            }
            new_blk->next = blk->next;
            blk->next = new_blk;
            blk = new_blk;

            // Construct element
            if (no_constructor) {
                *(element_type *)(blk->data) = data;
            } else {
                new (blk->data) element_type(std::forward<U>(data));
            }

            // Init tail and cache tail element position
            blk->cache_tail = 1;
            blk->tail.store(1, std::memory_order_relaxed);

            std::atomic_thread_fence(std::memory_order_release);
            // Move tail block node
            blk_tail_.store(blk, std::memory_order_relaxed);

            // Update capacity
            capacity_ += block_element_size_;
        }

        return true;
    }

    /*********************************************************************************
     * Pop
     ********************************************************************************/
    template <typename U>
    bool pop(U &data) {
        // Get tail block node
        auto blk = blk_head_.load(std::memory_order_relaxed);
        // Get head element position
        auto head = blk->head.load(std::memory_order_relaxed);

        if (head != blk->cache_tail ||
            head != (blk->cache_tail = blk->tail.load(std::memory_order_relaxed))) {
            std::atomic_thread_fence(std::memory_order_acquire);

            // Load element from block node data
            if (no_constructor) {
                data = *(element_type *)(blk->data + head * element_size);
            } else {
                auto elem = (element_type *)(blk->data + head * element_size);
                data = std::move(*elem);
                elem->~element_type();
            }

            // Get next head element position
            head = (head + 1) & block_element_size_mask_;

            std::atomic_thread_fence(std::memory_order_release);
            // Move head element position
            blk->head.store(head, std::memory_order_relaxed);
        } else if (blk != blk_tail_.load(std::memory_order_relaxed)) {
            std::atomic_thread_fence(std::memory_order_acquire);

            blk->cache_tail = blk->tail.load(std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_acquire);

            if (head == blk->cache_tail) {
                // Get next block node
                blk = blk->next;

                std::atomic_thread_fence(std::memory_order_release);
                // Move tail block node
                blk_head_.store(blk, std::memory_order_relaxed);

                // Get head element position
                head = blk->head.load(std::memory_order_relaxed);
                // Update cache tail of the block node
                blk->cache_tail = blk->tail.load(std::memory_order_relaxed);
                std::atomic_thread_fence(std::memory_order_acquire);
            }

            // Pop element data
            if (no_constructor) {
                data = *(element_type *)(blk->data + head * element_size);
            } else {
                auto elem = (element_type *)(blk->data + head * element_size);
                data = std::move(*elem);
                elem->~element_type();
            }

            // Get next head element position
            head = (head + 1) & block_element_size_mask_;

            std::atomic_thread_fence(std::memory_order_release);
            // Move head element position
            blk->head.store(head, std::memory_order_relaxed);
        } else {
            return false;
        }

        return true;
    }

    /*********************************************************************************
     * Empty
     ********************************************************************************/
    pump_inline bool empty() const noexcept {
        auto blk = blk_head_.load(std::memory_order_relaxed);
        auto head = blk->head.load(std::memory_order_relaxed);
        if (head != blk->tail.load(std::memory_order_relaxed)) {
            return false;
        } else if (blk != blk_tail_.load(std::memory_order_relaxed)) {
            return false;
        }
        return true;
    }

    /*********************************************************************************
     * Get capacity
     ********************************************************************************/
    pump_inline int32_t capacity() const noexcept {
        return capacity_;
    }

  private:
    /*********************************************************************************
     * Init list
     ********************************************************************************/
    void __init_list(int32_t blk_count) {
        // Create first block node.
        auto head = pump_object_create<block_node>();
        if (head == nullptr) {
            pump_abort();
        }
        head->data = (char *)pump_malloc(block_element_size_ * element_size);
        if (head->data == nullptr) {
            pump_abort();
        }

        auto tail = head;

        // Create left block nodes.
        for (int32_t i = 1; i < blk_count; i++) {
            // Create block node.
            tail->next = pump_object_create<block_node>();
            if (tail->next == nullptr) {
                pump_abort();
            }
            tail->next->data = (char *)pump_malloc(block_element_size_ * element_size);
            if (tail->next->data == nullptr) {
                pump_abort();
            }
            tail = tail->next;
        }

        // Link tail and head block nodes.
        tail->next = head;

        // Store head and tail block node.
        blk_head_.store(head, std::memory_order_release);
        blk_tail_.store(head, std::memory_order_release);

        // Update queue capacity.
        capacity_ = block_element_size_ * blk_count;
    }

  private:
    // Capacity
    int32_t capacity_;

    // Block element size
    int32_t block_element_size_;
    // Block element size mask
    int32_t block_element_size_mask_;

    // Head block node
    pump_cache_line_alignas std::atomic<block_node *> blk_head_;
    // Tail block node
    pump_cache_line_alignas std::atomic<block_node *> blk_tail_;
};

}  // namespace toolkit
}  // namespace pump

#endif
