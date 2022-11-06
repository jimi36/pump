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

#ifndef pump_toolkit_fl_mc_queue_h
#define pump_toolkit_fl_mc_queue_h

#include <atomic>
#include <chrono>

#include <pump/utils.h>
#include <pump/debug.h>
#include <pump/toolkit/features.h>

namespace pump {
namespace toolkit {

template <typename T, int32_t PerBlockElementCount = 1024>
class fl_mc_queue : public noncopyable {
  public:
    // Element type
    typedef T element_type;
    // Element type size
    constexpr static int32_t element_size = sizeof(element_type);

    // Element node
    struct element_node {
        element_node()
          : ready(0),
            next(this + 1) {
        }
        volatile int32_t ready;
        element_node *next;
        char data[element_size];
    };

    // Block node
    struct block_node {
        block_node *next;
        element_node elems[PerBlockElementCount];
    };

  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    fl_mc_queue(int32_t size)
      : capacity_(0),
        tail_block_node_(nullptr),
        head_(nullptr),
        tail_(nullptr) {
        __init_list(size);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~fl_mc_queue() {
        // Get next element node of the head element node.
        element_node *end_node = head_.load(std::memory_order_relaxed);
        // Get element head node.
        element_node *beg_node = tail_.load(std::memory_order_relaxed)->next;

        while (beg_node != end_node) {
            // Deconstruct element data.
            if (beg_node->ready == 1) {
                ((element_type *)beg_node->data)->~element_type();
            }
            // Move to next node.
            beg_node = beg_node->next;
        }

        while (tail_block_node_) {
            // Store next block node.
            block_node *tmp = tail_block_node_->next;
            // Delete block node.
            object_delete(tail_block_node_);
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
        element_node *next_write_node = head_.load(std::memory_order_relaxed);
        do {
            // If current write node is invalid, list is being extended and try
            // again.
            while (next_write_node == nullptr) {
                next_write_node = head_.load(std::memory_order_relaxed);
            }

            // If next write node is ready or is the tail node, list is full and
            // we need try to extend it.
            if (next_write_node->ready == 0 &&
                next_write_node->next !=
                    tail_.load(std::memory_order_relaxed)) {
                if (head_.compare_exchange_strong(
                        next_write_node,
                        next_write_node->next,
                        std::memory_order_acquire,
                        std::memory_order_relaxed)) {
                    break;
                }
            } else {
                if (__extend_list(next_write_node)) {
                    break;
                }
            }
        } while (true);

        // Construct node data.
        new (next_write_node->data) element_type(std::forward<U>(data));

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
        element_node *current_tail = tail_.load(std::memory_order_relaxed);

        do {
            // Get next read node.
            next_read_node = current_tail->next;

            // If next read node is not ready just return false.
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
        element_type *elem = (element_type *)next_read_node->data;
        data = std::move(*elem);
        elem->~element_type();

        // Mark next read node not ready.
        next_read_node->ready = 0;

        return true;
    }

    /*********************************************************************************
     * Empty
     ********************************************************************************/
    pump_inline bool empty() const pump_noexcept {
        element_node *tail = tail_.load(std::memory_order_relaxed)->next;
        return tail == head_.load(std::memory_order_relaxed);
    }

    /*********************************************************************************
     * Get capacity
     ********************************************************************************/
    pump_inline int32_t capacity() const pump_noexcept {
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
        tail_block_node_ = object_create<block_node>();

        // Get head and tail element node.
        element_node *head = tail_block_node_->elems + 0;
        element_node *tail = tail_block_node_->elems + PerBlockElementCount - 1;

        // Update list capacity.
        capacity_.fetch_add(PerBlockElementCount, std::memory_order_relaxed);

        for (size -= PerBlockElementCount; size > 0;
             size -= PerBlockElementCount) {
            // Insert new block node.
            block_node *bnode = object_create<block_node>();
            bnode->next = tail_block_node_;
            tail_block_node_ = bnode;

            // Insert new element nodes.
            tail->next = bnode->elems + 0;
            tail = bnode->elems + PerBlockElementCount - 1;

            // Update list capacity.
            capacity_.fetch_add(PerBlockElementCount,
                                std::memory_order_relaxed);
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
        block_node *bnode = object_create<block_node>();
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
    // Element capacity
    std::atomic_int32_t capacity_;
    // Tail block node
    block_node *tail_block_node_;
    // Head element node
    char padding1_[64];
    std::atomic<element_node *> head_;
    // Tail element node
    char padding_[64];
    std::atomic<element_node *> tail_;
};

}  // namespace toolkit
}  // namespace pump

#endif
