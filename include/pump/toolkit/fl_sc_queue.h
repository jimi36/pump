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

#ifndef pump_toolkit_fl_sc_queue_h
#define pump_toolkit_fl_sc_queue_h

#include <atomic>
#include <chrono>

#include "pump/utils.h"
#include "pump/debug.h"
#include "pump/toolkit/features.h"

namespace pump {
namespace toolkit {

template <typename T, int32_t PerBlockElementCount = 1024>
class LIB_PUMP fl_sc_queue : public noncopyable {
  public:
    // Element type
    typedef T element_type;
    // Element size
    constexpr static int32_t element_size = sizeof(element_type);

    // Block node
    struct block_node {
        block_node() :
            next(nullptr),
            data(nullptr),
            head(0),
            cache_tail(0),
            tail(0),
            cache_head(0) {}
        block_node *next;
        block_t *data;

        block_t padding1_[64];
        std::atomic_int32_t head;
        int32_t cache_tail;

        block_t padding2_[64];
        std::atomic_int32_t tail;
        int32_t cache_head;
    };

  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    fl_sc_queue(int32_t size) :
        capacity_(0),
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
    ~fl_sc_queue() {
        // Get head block node.
        block_node *head_blk = blk_head_.load(std::memory_order_relaxed);
        // Get tail block node.
        block_node *tail_blk = blk_tail_.load(std::memory_order_relaxed);

        do {
            // Get head and tail element position
            int32_t head = head_blk->head.load(std::memory_order_relaxed);
            int32_t tail = head_blk->tail.load(std::memory_order_relaxed);

            while (head != tail) {
                // Destory element
                auto elem = (element_type *)(head_blk->data + head * element_size);
                elem->~element_type();
                // Move next element position
                head = (head + 1) & block_element_size_mask_;
            }

            // Next block pointer.
            block_node *next_blk = head_blk->next;
            // Free block.
            pump_free(head_blk->data);
            object_delete(head_blk);
            // Move to next node.
            head_blk = next_blk;

        } while (head_blk != tail_blk);
    }

    /*********************************************************************************
     * Push
     ********************************************************************************/
    template <typename U> bool push(U &&data) {
        // Get tail block node
        block_node *blk = blk_tail_.load(std::memory_order_relaxed);
        // Get tail element position
        int32_t tail = blk->tail.load(std::memory_order_relaxed);
        // Get next tail element position
        int32_t next_tail = (tail + 1) & block_element_size_mask_;

        if (next_tail != blk->cache_head ||
            next_tail != (blk->cache_head = blk->head.load(std::memory_order_relaxed))) {
            std::atomic_thread_fence(std::memory_order_acquire);

            // Construct element
            new (blk->data + tail * element_size) element_type(std::forward<U>(data));

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
            new (blk->data + tail * element_size) element_type(std::forward<U>(data));

            // Get next tail element position
            next_tail = (tail + 1) & block_element_size_mask_;

            std::atomic_thread_fence(std::memory_order_release);
            // Move tail position of block
            blk->tail.store(next_tail, std::memory_order_relaxed);
            // Move tail block node
            blk_tail_.store(blk, std::memory_order_relaxed);
        } else {
            // Create new block node
            block_node *new_blk = object_create<block_node>();
            new_blk->data = (block_t *)pump_malloc(block_element_size_ * element_size);
            new_blk->next = blk->next;
            blk->next = new_blk;
            blk = new_blk;

            // Construct element
            new (blk->data) element_type(std::forward<U>(data));

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
    template <typename U> bool pop(U &data) {
        // Get tail block node
        block_node *blk = blk_head_.load(std::memory_order_relaxed);
        // Get head element position
        int32_t head = blk->head.load(std::memory_order_relaxed);

        if (head != blk->cache_tail ||
            head != (blk->cache_tail = blk->tail.load(std::memory_order_relaxed))) {
            std::atomic_thread_fence(std::memory_order_acquire);

            // Load element from block node data
            element_type *elem = (element_type *)(blk->data + head * element_size);
            data = std::move(*elem);
            elem->~element_type();

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
            element_type *elem = (element_type *)(blk->data + head * element_size);
            data = std::move(*elem);
            elem->~element_type();

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
    PUMP_INLINE bool empty() const {
        block_node *blk = blk_head_.load(std::memory_order_relaxed);
        int32_t head = blk->head.load(std::memory_order_relaxed);
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
    PUMP_INLINE int32_t capacity() const {
        return capacity_;
    }

  private:
    /*********************************************************************************
     * Init list
     ********************************************************************************/
    void __init_list(int32_t blk_count) {
        // Create first block node.
        block_node *head = object_create<block_node>();
        head->data = (block_t *)pump_malloc(block_element_size_ * element_size);
        block_node *tail = head;

        // Create left block nodes.
        for (int32_t i = 1; i < blk_count; i++) {
            // Create block node.
            tail->next = object_create<block_node>();
            tail->next->data = (block_t *)pump_malloc(block_element_size_ * element_size);
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
    block_t padding1_[64];
    std::atomic<block_node *> blk_head_;
    // Tail block node
    block_t padding2_[64];
    std::atomic<block_node *> blk_tail_;
};

}  // namespace toolkit
}  // namespace pump

#endif
