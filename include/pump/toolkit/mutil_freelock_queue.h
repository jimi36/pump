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

#ifndef pump_toolkit_mutil_freelock_queue_h
#define pump_toolkit_mutil_freelock_queue_h

#include <atomic>
#include <chrono>

#include "pump/utils.h"
#include "pump/debug.h"
#include "pump/toolkit/features.h"

namespace pump {
namespace toolkit {

    template <typename T, int PerBlockElementCount = 32>
    class LIB_PUMP mutil_freelock_queue
      : public noncopyable {

      public:
        // Element type
        typedef T element_type;
        // Element type size
        constexpr static int32_t element_size = sizeof(element_type);

        // List element node
        struct list_element_node {
            list_element_node() : next(this+1), ready(false) {
            }
            block_t data[element_size];
            list_element_node *next;
            std::atomic_bool ready;
        };
        // Element node type
        typedef list_element_node element_node;

        // List block node
        struct list_block_node {
            list_block_node() : next(nullptr) {
            }
            list_block_node *next;
            element_node elems[PerBlockElementCount];
        };
        typedef list_block_node block_node;

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        mutil_freelock_queue(int32_t size)
          : tail_block_node_(nullptr),
            capacity_(0),
            head_(nullptr), 
            tail_(nullptr) {
            __init_list(size);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~mutil_freelock_queue() {
            // Get element head node.
            element_node *beg_node = tail_.load(std::memory_order_relaxed)->next;
            // Get next element node of the head element node.
            element_node *end_node = head_.load(std::memory_order_relaxed);

            while (beg_node != end_node) {
                // Deconstruct element data.
                if (beg_node->ready.load(std::memory_order_relaxed)) {
                    ((element_type*)beg_node->data)->~element_type();
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
         * Push by lvalue
         ********************************************************************************/
        PUMP_INLINE bool push(const element_type &data) {
            return push(std::move(data));
        }

        /*********************************************************************************
         * Push by rvalue
         ********************************************************************************/
        template <typename U>
        bool push(U &&data) {
            element_node *next_write_node = nullptr;
            do {
                // Get current head node as write node.
                next_write_node = head_.load(std::memory_order_relaxed);

                // If current write node is invalid, list is being extended and try again.
                if (next_write_node == nullptr) {
                    continue;
                }

                // If next write node is the tail node, list is full and try to extend it.
                if (next_write_node->next != tail_.load(std::memory_order_acquire)) {
                    // Update list head node to next node.
                    if (head_.compare_exchange_strong(next_write_node,
                                                      next_write_node->next,
                                                      std::memory_order_acquire,
                                                      std::memory_order_relaxed)) {
                        break;
                    }
                } else {
                    // Extend list after next wirte node.
                    if (__extend_list(next_write_node)) {
                        break;
                    }
                }
            } while (true);

            // Wait current write node be not ready.
            while (next_write_node->ready.load(std::memory_order_relaxed));

            // Construct node data.
            new (next_write_node->data) element_type(data);

            // Mark node ready.
            next_write_node->ready.store(true, std::memory_order_release);

            return true;
        }

        /*********************************************************************************
         * Pop
         ********************************************************************************/
        template <typename U>
        bool pop(U &data) {
            element_node *current_tail = nullptr;
            element_node *next_read_node = nullptr;
            do {
                // Get current tail node.
                current_tail = tail_.load(std::memory_order_relaxed);
                // Get next read node.
                next_read_node = current_tail->next;

                // Check next read node is ready or not.
                if (!next_read_node->ready.load(std::memory_order_acquire)) {
                    return false;
                }

                // Update tail node to next node.
                if (tail_.compare_exchange_strong(current_tail,
                                                  next_read_node,
                                                  std::memory_order_acquire,
                                                  std::memory_order_relaxed)) {
                    break;
                }
            } while (true);

            // Copy and destory node data.
            element_type *elem = (element_type*)next_read_node->data;
            data = std::move(*elem);
            elem->~element_type();

            // Mark next read node not ready.
            next_read_node->ready.store(false, std::memory_order_release);

            return true;
        }

        /*********************************************************************************
         * Empty
         ********************************************************************************/
        PUMP_INLINE bool empty() const {
            element_node *tail = tail_.load(std::memory_order_relaxed)->next;
            return tail == head_.load(std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Get capacity
         ********************************************************************************/
        PUMP_INLINE int32_t capacity() const {
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
            capacity_.fetch_add(PerBlockElementCount, std::memory_order_release);

            for (int32_t i = PerBlockElementCount; i < size; i += PerBlockElementCount) {
                // Create new element block node.
                block_node *bnode = object_create<block_node>();
                // Link block node.
                bnode->next = tail_block_node_;
                tail_block_node_ = bnode;

                // Update tail element node.
                tail->next = bnode->elems + 0;
                tail = bnode->elems + PerBlockElementCount - 1;

                // Update list capacity.
                capacity_.fetch_add(PerBlockElementCount, std::memory_order_release);
            }

            // Link tail and head node.
            tail->next = head;

            // Store head and tail element node.
            head_.store(head, std::memory_order_release);
            tail_.store(tail, std::memory_order_release);
        }

        /*********************************************************************************
         * Extend list
         ********************************************************************************/
        bool __extend_list(element_node *head) {
            // Empty element node.
            //element_node *empty_node = nullptr;
            // Lock the current head element node.
            if (!head_.compare_exchange_strong(head,
                                               nullptr,
                                               std::memory_order_acquire,
                                               std::memory_order_relaxed)) {
                return false;
            }

            // Create new block node.
            block_node *bnode = object_create<block_node>();
            // Link block node.
            bnode->next = tail_block_node_;
            tail_block_node_ = bnode;

            // Append new element nodes to circle element node list.
            (bnode->elems + PerBlockElementCount - 1)->next = head->next;
            head->next = bnode->elems + 0;

            // Update head node to the next node of current head node.
            head_.store(head->next, std::memory_order_release);

            // Update list capacity.
            capacity_.fetch_add(PerBlockElementCount, std::memory_order_relaxed);

            return true;
        }

      private:
        // Tail block node
        block_node *tail_block_node_;
        // Element capacity
        std::atomic_int32_t capacity_;
        // Head element node
        block_t padding1_[64];
        std::atomic<element_node*> head_;
        // Tail element node
        block_t padding_[64];
        std::atomic<element_node*> tail_;
    };

}  // namespace toolkit
}  // namespace pump

#endif