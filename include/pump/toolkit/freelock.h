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

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        freelock_array_queue(uint32_t size)
            : size_(size),
              mem_block_(nullptr),
              write_index_(0),
              max_write_index_(0),
              read_index_(0),
              max_read_index_(0) {
            mem_block_ = (block_t*)pump_malloc(size * element_size);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~freelock_array_queue() {
            if (mem_block_) {
                int32_t read_index = read_index_.load();
                int32_t max_read_index = max_read_index_.load();
                while (__count_to_index(read_index) != __count_to_index(max_read_index)) {
                    ((element_type*)mem_block_ + __count_to_index(read_index++))
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
            int32_t cur_write_index = write_index_.load(std::memory_order_relaxed);
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
                cur_write_index = write_index_.load(std::memory_order_acquire);
            } while (true);

            // Construct element object
            new ((element_type*)mem_block_ + __count_to_index(cur_write_index)) element_type(data);

            while (!max_read_index_.compare_exchange_weak(cur_write_index,
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
                int32_t cur_read_index = read_index_.load(std::memory_order_relaxed);
                int32_t array_read_index = __count_to_index(cur_read_index);
                if (array_read_index == __count_to_index(max_read_index_.load(std::memory_order_acquire))) {
                    return false;
                }

                if (read_index_.compare_exchange_strong(cur_read_index,
                                                        cur_read_index + 1,
                                                        std::memory_order_acquire,
                                                        std::memory_order_relaxed)) {
                    // Copy element.
                    element_type &elem = *((element_type*)mem_block_ + array_read_index);
                    data = elem;

                    // Deconstruct element.
                    elem.~element_type();

                    while (!max_write_index_.compare_exchange_weak(cur_read_index,
                                                                   cur_read_index + 1,
                                                                   std::memory_order_relaxed,
                                                                   std::memory_order_relaxed)) {
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
            return (count % size_);
        }

      private:
        // Capacity size
        int32_t size_;

        // Element memory block
        block_t *mem_block_;

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

    template <typename T, int PerBlockElementCount = 32>
    class LIB_PUMP freelock_list_queue
      : public noncopyable {

      public:
        // Element type
        typedef T element_type;
        // Element type size
        const static int32_t element_size = sizeof(element_type);

        // List element node
        struct list_element_node {
            list_element_node() : next(this+1), ready(false) {
            }
            block_t data[element_size];
            list_element_node* next;
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
        freelock_list_queue(int32_t size)
          : tail_block_node_(nullptr),
            capacity_(0),
            head_(nullptr), 
            tail_(nullptr) {
            __init_list(size);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~freelock_list_queue() {
            // Get element head node.
            element_node *head = head_.load(std::memory_order_relaxed);
            // Get next element node of the head element node.
            element_node *node = head->next;
            // Break element node circle list.
            head->next = nullptr;

            while (node != nullptr) {
                // Deconstruct element data.
                if (node->ready.load(std::memory_order_relaxed)) {
                    ((element_type*)node->data)->~element_type();
                }
                // Move to next node.
                node = node->next;
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
                if (!next_read_node->ready.load(std::memory_order_consume)) {
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
            element_node *empty_node = nullptr;
            // Lock the current head element node.
            if (!head_.compare_exchange_strong(head,
                                               empty_node,
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
        std::atomic<element_node *> head_;
        // Atomic padding
        block_t padding_[64];
        // Tail element node
        std::atomic<element_node *> tail_;
    };

    template <typename Q>
    class LIB_PUMP block_freelock_queue 
      : public noncopyable {

      public:
        // Inner queue type
        typedef Q inner_queue_type;
        // Queue element type
        typedef typename inner_queue_type::element_type element_type;

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        block_freelock_queue(uint32_t size = 1024)
          : queue_(size) {
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~block_freelock_queue() {
        }

        /*********************************************************************************
         * Enqueue
         ********************************************************************************/
        bool enqueue(const element_type &item) {
            if (PUMP_LIKELY(queue_.push(item))) {
                semaphone_.signal();
                return true;
            }
            return false;
        }
        bool enqueue(element_type &&item) {
            if (PUMP_LIKELY(queue_.push(item))) {
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
                while (!queue_.pop(item)) {
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
        bool dequeue(U &item, uint64_t timeout) {
            if (semaphone_.wait(timeout)) {
                while (!queue_.pop(item)) {
                    continue;
                }
                return true;
            }
            return false;
        }

        template <typename U, typename Rep, typename Period>
        bool dequeue(U &item, const std::chrono::duration<Rep, Period> &timeout) {
            if (semaphone_.wait(
                    std::chrono::duration_cast<std::chrono::microseconds>(timeout).count())) {
                while (!queue_.pop(item)) {
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
                while (!queue_.pop(item)) {
                    continue;
                }
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Empty
         ********************************************************************************/
        bool empty() {
            return queue_.empty();
        }

      private:
        inner_queue_type queue_;
        light_semaphore semaphone_;
    };

}  // namespace toolkit
}  // namespace pump

#endif