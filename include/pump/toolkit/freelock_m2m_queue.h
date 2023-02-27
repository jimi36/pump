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

#ifndef pump_toolkit_freelock_m2m_queue_h
#define pump_toolkit_freelock_m2m_queue_h

#include <atomic>
#include <chrono>

#include <pump/utils.h>
#include <pump/debug.h>
#include <pump/toolkit/features.h>

namespace pump {
namespace toolkit {

/*********************************************************************************
 * The freelock_m2m_queue is freelock queue, and its use case is that many
 * producers and many consumers push and pop elements at the same time.
 ********************************************************************************/
template <typename T, int32_t PerBlockElementCount = 1024>
class freelock_m2m_queue : public noncopyable {
  public:
    // Element type
    typedef T element_type;
    // Element type size
    constexpr static int32_t element_size = sizeof(element_type);
    // Element no constructor flag
    constexpr static bool no_constructor =
        std::is_integral<element_type>::value ||
        std::is_pointer<element_type>::value;

    // Element node
    struct element_node {
        element_node()
          : next(this + 1),
            ready(0) {
        }

        element_node *next;

        volatile int32_t ready;

        char data[element_size];
    };

    // Block node
    struct block_node {
        block_node()
          : next(nullptr) {
        }

        block_node *next;

        element_node elems[PerBlockElementCount];
    };

  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    freelock_m2m_queue(int32_t size)
      : tail_block_node_(nullptr),
        capacity_(0),
        head_(nullptr),
        tail_(nullptr) {
        __init_list(size);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~freelock_m2m_queue() {
        if (!no_constructor) {
            // Get next element node of the head element node.
            auto end_node = head_.load(std::memory_order_relaxed);
            // Get element head node.
            auto beg_node = tail_.load(std::memory_order_relaxed)->next;

            while (beg_node != end_node) {
                // Deconstruct element data.
                if (beg_node->ready == 1) {
                    ((element_type *)beg_node->data)->~element_type();
                }
                // Move to next node.
                beg_node = beg_node->next;
            }
        }

        while (tail_block_node_) {
            // Store next block node.
            auto tmp = tail_block_node_->next;
            // Delete block node.
            pump_object_destroy(tail_block_node_);
            // Move to next node.
            tail_block_node_ = tmp;
        }
    }

    /*********************************************************************************
     * Push
     ********************************************************************************/
    template <typename U>
    bool push(U &&data) {
        // Get current head node as write node.
        auto next_write_node = head_.load(std::memory_order_acquire);
        do {
            // If current write node is invalid, list is being extended and try
            // again.
            while (next_write_node == nullptr) {
                next_write_node = head_.load(std::memory_order_relaxed);
            }

            // If next write node is ready or is the tail node, list is full and
            // we need try to extend it.
            if (next_write_node->next != tail_.load(std::memory_order_relaxed)) {
                if (head_.compare_exchange_strong(
                        next_write_node,
                        next_write_node->next,
                        std::memory_order_release,
                        std::memory_order_relaxed)) {
                    break;
                }
            } else {
                if (__extend_list(next_write_node)) {
                    break;
                }
            }
        } while (true);

        // Wait node is unready.
        while (next_write_node->ready == 1) {
        }

        // Construct node data.
        if (no_constructor) {
            *(element_type *)(next_write_node->data) = data;
        } else {
            new (next_write_node->data) element_type(std::forward<U>(data));
        }

        // Mark node ready.
        next_write_node->ready = 1;

        return true;
    }

    /*********************************************************************************
     * Pop
     ********************************************************************************/
    template <typename U>
    bool pop(U &data) {
        // Next read node.
        element_node *next_read_node = nullptr;

        // Get current tail node.
        auto current_tail = tail_.load(std::memory_order_acquire);

        do {
            // Get next read node.
            next_read_node = current_tail->next;
            if (next_read_node->ready == 0) {
                return false;
            }

            // Update tail node to next node.
            if (tail_.compare_exchange_strong(
                    current_tail,
                    next_read_node,
                    std::memory_order_release,
                    std::memory_order_relaxed)) {
                break;
            }
        } while (true);

        // Pop element data.
        if (no_constructor) {
            data = *(element_type *)(next_read_node->data);
        } else {
            auto elem = (element_type *)next_read_node->data;
            data = std::move(*elem);
            elem->~element_type();
        }

        // Mark read node not ready.
        next_read_node->ready = 0;

        return true;
    }

    /*********************************************************************************
     * Empty
     ********************************************************************************/
    pump_inline bool empty() const noexcept {
        auto tail = tail_.load(std::memory_order_relaxed)->next;
        return tail == head_.load(std::memory_order_relaxed);
    }

    /*********************************************************************************
     * Get capacity
     ********************************************************************************/
    pump_inline int32_t capacity() const noexcept {
        return capacity_.load(std::memory_order_relaxed);
    }

  private:
    /*********************************************************************************
     * Init list
     ********************************************************************************/
    void __init_list(int32_t size) {
        // Init size must be greater or equal than per_block_element_count.
        size = size > PerBlockElementCount ? size : PerBlockElementCount;

        // Create first block node.
        tail_block_node_ = pump_object_create<block_node>();
        if (tail_block_node_ == nullptr) {
            pump_abort();
        }

        // Get head and tail element node.
        auto head = tail_block_node_->elems + 0;
        auto tail = tail_block_node_->elems + PerBlockElementCount - 1;

        // Update list capacity.
        capacity_.fetch_add(PerBlockElementCount, std::memory_order_relaxed);

        for (size -= PerBlockElementCount; size > 0;
             size -= PerBlockElementCount) {
            // Insert new block node.
            auto bnode = pump_object_create<block_node>();
            if (bnode == nullptr) {
                pump_abort();
            }
            bnode->next = tail_block_node_;
            tail_block_node_ = bnode;

            // Insert new element nodes.
            tail->next = bnode->elems + 0;
            tail = bnode->elems + PerBlockElementCount - 1;

            // Update list capacity.
            capacity_.fetch_add(PerBlockElementCount, std::memory_order_relaxed);
        }

        // Link tail and head node.
        tail->next = head;

        // Store head and tail element node.
        head_.store(head, std::memory_order_relaxed);
        tail_.store(tail, std::memory_order_relaxed);
    }

    /*********************************************************************************
     * Extend list
     ********************************************************************************/
    bool __extend_list(element_node *&enode) {
        // Try to lock the element list head node.
        if (!head_.compare_exchange_strong(
                enode,
                nullptr,
                std::memory_order_acquire,
                std::memory_order_relaxed)) {
            return false;
        }

        // Insert new block node.
        auto bnode = pump_object_create<block_node>();
        if (bnode == nullptr) {
            head_.store(enode, std::memory_order_release);
            return false;
        }

        bnode->next = tail_block_node_;
        tail_block_node_ = bnode;

        // Insert new element nodes.
        bnode->elems[PerBlockElementCount - 1].next = enode->next;
        enode->next = bnode->elems;

        // Update element list head node to the next node.
        head_.store(enode->next, std::memory_order_release);

        // Update list capacity.
        capacity_.fetch_add(PerBlockElementCount, std::memory_order_relaxed);

        return true;
    }

  private:
    // Tail block node
    block_node *tail_block_node_;

    // Element capacity
    pump_cache_line_alignas std::atomic_int32_t capacity_;

    // Head element node
    pump_cache_line_alignas std::atomic<element_node *> head_;

    // Tail element node
    pump_cache_line_alignas std::atomic<element_node *> tail_;
};

}  // namespace toolkit
}  // namespace pump

#endif
