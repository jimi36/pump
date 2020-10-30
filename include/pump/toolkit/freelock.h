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
    class LIB_PUMP freelock_array_queue : public noncopyable {
      public:
        // Element type
        typedef T element_type;
        // Element type size
        const static uint32 element_size = sizeof(element_type);

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        freelock_array_queue(uint32 size)
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
        ~freelock_array_queue() {
            if (mem_block_) {
                int32 read_index = read_index_.load();
                int32 max_read_index = max_read_index_.load();
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
            int32 cur_write_index = write_index_.load(std::memory_order_relaxed);
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
            } while (true);

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
                int32 cur_read_index = read_index_.load(std::memory_order_relaxed);
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
            } while (true);  // keep looping to try again!

            // Something went wrong. it shouldn't be possible to reach here
            PUMP_ASSERT(0);

            // Add this return statement to avoid compiler warnings
            return false;
        }

        /*********************************************************************************
         * Get size
         ********************************************************************************/
        int32 size() {
            int32 cur_read_index = read_index_.load(std::memory_order_relaxed);
            int32 cur_write_index = write_index_.load(std::memory_order_relaxed);

            if (cur_write_index >= cur_read_index) {
                return (cur_write_index - cur_read_index);
            } else {
                return (size_ + cur_write_index - cur_read_index);
            }
        }

        /*********************************************************************************
         * Empty
         ********************************************************************************/
        bool empty() {
            return size() > 0;
        }

        /*********************************************************************************
         * Get capacity
         ********************************************************************************/
        int32 capacity() {
            return size_;
        }

      private:
        /*********************************************************************************
         * Map count to index
         ********************************************************************************/
        PUMP_INLINE int32 count_to_index(int32 count) {
            return (count % size_);
        }

      private:
        // Capacity size
        int32 size_;

        // Element memory block
        block_ptr mem_block_;

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

    template <typename T>
    class LIB_PUMP freelock_vector_queue : public noncopyable {
      public:
        // Freelock array queue type
        typedef freelock_array_queue<T> freelock_array_type;
        // Array element type
        typedef typename freelock_array_type::element_type element_type;

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        freelock_vector_queue(uint32 capacity)
            : array_(nullptr), resize_locker_(false), concurrent_cnt_(0) {
            array_ = object_create<freelock_array_type>(capacity);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~freelock_vector_queue() {
            if (array_) {
                object_delete(array_);
            }
        }

        /*********************************************************************************
         * Push
         * It will new a bigger array if current array is full. So this function always
         * return true, thread safe.
         ********************************************************************************/
        bool push(const element_type &data) {
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

        /*********************************************************************************
         * Get size
         ********************************************************************************/
        int32 size() {
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

                int32 size = array_->size();

                // sub concurrent count if resize locker locked
                concurrent_cnt_.fetch_sub(1, std::memory_order_release);

                return size;
            }

            return 0;
        }

        /*********************************************************************************
         * Empty
         ********************************************************************************/
        bool empty() {
            return size() > 0;
        }

        /*********************************************************************************
         * Get capacity
         ********************************************************************************/
        int32 capacity() {
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

                int32 capacity = array_->capacity();

                // sub concurrent count if resize locker locked
                concurrent_cnt_.fetch_sub(1, std::memory_order_release);

                return capacity;
            }

            return 0;
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
            freelock_array_type *new_array = object_create<freelock_array_type>(capacity);

            element_type data;
            while (array_->pop(data)) {
                new_array->push(data);
            }

            object_delete(array_);

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
    class LIB_PUMP freelock_list_queue : public noncopyable {
      public:
        // Element type
        typedef T element_type;
        // Element type size
        const static int32 element_size = sizeof(element_type);
        // Element list node
        struct element_node {
            element_node() : ready(false), next(nullptr) {
            }
            block data[element_size];
            std::atomic_bool ready;
            element_node *next;
        };

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        freelock_list_queue(int32 size)
            : head_(nullptr), 
              tail_(nullptr), 
              capacity_(0) {
            __init_list(size);
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~freelock_list_queue() {
            element_node *head = head_.load(std::memory_order_relaxed);
            element_node *node = head->next;
            head->next = nullptr;
            while (node != nullptr) {
                element_node *tmp = node->next;

                if (node->ready.load(std::memory_order_relaxed)) {
                    ((element_type *)node->data)->~element_type();
                }
                object_delete(node);

                node = tmp;
            }
        }

        /*********************************************************************************
         * Push
         ********************************************************************************/
        bool push(const element_type &data) {
            int32 count_down_to_extend = 100;
            element_node *current_head = nullptr;

            while (true) {
                // Get current head node.
                current_head = head_.load(std::memory_order_consume);

                // If current head node is invalid, list is being extended and try again.
                if (PUMP_UNLIKELY(current_head == nullptr)) {
                    continue;
                }

                // If next node head is tail node, list may need be extended.
                if (PUMP_LIKELY(current_head->next != tail_.load(std::memory_order_consume))) {
                    // Update list head node to next node.
                    if (head_.compare_exchange_strong(current_head,
                                                      current_head->next,
                                                      std::memory_order_release,
                                                      std::memory_order_relaxed)) {
                        break;
                    }
                } else {
                    // Count down to extend list.
                    if (PUMP_UNLIKELY(--count_down_to_extend <= 0)) {
                        // Extend list after current head node.
                        if (PUMP_LIKELY(__extend_list(current_head))) {
                            break;
                        }
                    }
                }
            }

            // Copy data to the node.
            new (current_head->data) element_type(data);

            // Mark node ready.
            current_head->ready.store(true, std::memory_order_release);

            return true;
        }

        /*********************************************************************************
         * Pop
         ********************************************************************************/
        template <typename U>
        bool pop(U &data) {
            element_node *current_tail = nullptr;
            element_node *next_read_node = nullptr;

            while (true) {
                // Get current tail node.
                current_tail = tail_.load(std::memory_order_consume);
                // Get next read node.
                next_read_node = current_tail->next;

                // Check next read node is ready or not.
                if (PUMP_LIKELY(next_read_node->ready.load(std::memory_order_consume))) {
                    // Update tail node to next node.
                    if (tail_.compare_exchange_strong(current_tail,
                                                      next_read_node,
                                                      std::memory_order_release,
                                                      std::memory_order_relaxed)) {
                        break;
                    }
                }

                // Next read node equal to the head node, means no data and return.
                if (PUMP_UNLIKELY(next_read_node == head_.load(std::memory_order_consume))) {
                    return false;
                }
            }

            // Copy and destory node data.
            element_type *elem = (element_type *)next_read_node->data;
            data = *elem;
            elem->~element_type();

            // Mark next read node not ready.
            next_read_node->ready.store(false, std::memory_order_release);

            return true;
        }

        /*********************************************************************************
         * Empty
         ********************************************************************************/
        bool empty() {
            return tail_.load(std::memory_order_relaxed)->next == 
                        head_.load(std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Get capacity
         ********************************************************************************/
        int32 capacity() {
            return capacity_.load(std::memory_order_relaxed);
        }

      private:
        /*********************************************************************************
         * Init list
         ********************************************************************************/
        void __init_list(int32 size) {
            // Init size must be greater or equal than 32.
            size = size > 32 ? size : 32;

            // Create first node as tail.
            element_node *tail = object_create<element_node>();
            // Store head node.
            head_.store(tail, std::memory_order_release);
            for (int32 i = 1; i < size; i++) {
                tail->next = object_create<element_node>();
                tail = tail->next;
            }
            // Connect tail and head node.
            tail->next = head_.load(std::memory_order_acquire);
            // Store tail node.
            tail_.store(tail, std::memory_order_release);

            // Update list capacity.
            capacity_.fetch_add(size, std::memory_order_relaxed);
        }

        /*********************************************************************************
         * Extend list
         ********************************************************************************/
        bool __extend_list(element_node *current_head) {
            // Empty node
            element_node *empty_node = nullptr;
            element_node *current_head_next = current_head->next;

            // Update head node to lock node for locking.
            if (!head_.compare_exchange_strong(current_head,
                                               empty_node,
                                               std::memory_order_acquire,
                                               std::memory_order_relaxed)) {
                return false;
            }

            // Extend list by insert nodes after current head node.
            int32 extend_size = 32;
            element_node *node = current_head;
            for (int32 i = 0; i < extend_size; i++) {
                node->next = object_create<element_node>();
                node = node->next;
            }
            node->next = current_head_next;

            // Update head node to current head next node for unlocking.
            head_.compare_exchange_strong(empty_node,
                                          current_head->next,
                                          std::memory_order_acquire,
                                          std::memory_order_relaxed);

            // Update list capacity.
            capacity_.fetch_add(extend_size, std::memory_order_relaxed);

            return true;
        }

      private:
        // List head node
        std::atomic<element_node *> head_;
        // List tail node
        std::atomic<element_node *> tail_;
        // List capacity
        std::atomic_int32_t capacity_;
    };

    template <typename Q>
    class LIB_PUMP block_freelock_queue : public noncopyable {
      public:
        // Inner queue type
        typedef Q inner_queue_type;
        // Queue element type
        typedef typename inner_queue_type::element_type element_type;

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        block_freelock_queue(uint32 init_size = 1024) : queue_(init_size) {
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
        bool dequeue(U &item, uint64 timeout) {
            if (semaphone_.wait(timeout)) {
                while (!queue_.pop(item)) {
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