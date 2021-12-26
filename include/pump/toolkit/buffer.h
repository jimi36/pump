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

#ifndef pump_toolkit_buffer_h
#define pump_toolkit_buffer_h

#include <atomic>

#include "pump/debug.h"
#include "pump/types.h"
#include "pump/memory.h"
#include "pump/platform.h"

namespace pump {
namespace toolkit {

    class LIB_PUMP base_buffer {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        base_buffer() noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~base_buffer();

        /*********************************************************************************
         * Get raw buffer pointer
         ********************************************************************************/
        PUMP_INLINE const block_t* raw() const {
            return raw_;
        }
        PUMP_INLINE block_t* raw() {
            return raw_;
        }

        /*********************************************************************************
         * Get buffer capacity
         ********************************************************************************/
        PUMP_INLINE uint32_t capacity() const {
            return raw_size_;
        }

      protected:
        /*********************************************************************************
         * Init by allocate
         * Allocate a memory with the size.
         ********************************************************************************/
        bool __init_by_allocate(uint32_t size);

        /*********************************************************************************
         * Init by copy
         * Allocate a memory block and copy input buffer to the buffer memory block.
         ********************************************************************************/
        bool __init_by_copy(const block_t *b, uint32_t size);

        /*********************************************************************************
         * Init by move
         * The input buffer will be moved to the buffer.
         ********************************************************************************/
        bool __init_by_move(const block_t *b, uint32_t size);
        
      protected:
        // Raw buffer
        block_t *raw_;
        // Raw buffer size
        uint32_t raw_size_;
    };

    class io_buffer
      : public base_buffer {

      public:
        /*********************************************************************************
         * Create
         ********************************************************************************/
        static io_buffer* create() {
            INLINE_OBJECT_CREATE(obj, io_buffer, ());
            return obj;
        }

        /*********************************************************************************
         * Init
         * Allocate a memory with the size.
         ********************************************************************************/
        PUMP_INLINE bool init(uint32_t size) {
            return __init_by_allocate(size);
        }

        /*********************************************************************************
         * Append
         * Append input buffer by copying. If there is no enough memory block to use, the
         * buffer will allocate a new memory block.
         ********************************************************************************/
        bool append(const block_t *b, uint32_t size);

        /*********************************************************************************
         * Shift
         * Return current size.
         ********************************************************************************/
        PUMP_INLINE uint32_t shift(uint32_t size) {
            PUMP_ASSERT(size_ >= size);
            if (size_ == 0 || size_ < size) {
                return 0;
            }
            read_pos_ += size;
            size_ -= size;
            return size_;
        }

        /*********************************************************************************
         * Get data pointer
         ********************************************************************************/
        PUMP_INLINE const block_t *data() const {
            return size_ == 0 ? nullptr : (raw_ + read_pos_);
        }

        /*********************************************************************************
         * Get data size
         ********************************************************************************/
        PUMP_INLINE uint32_t size() const {
            return size_;
        }

        /*********************************************************************************
         * Reset
         ********************************************************************************/
        PUMP_INLINE void reset() {
            size_ = read_pos_ = 0;
        }

        /*********************************************************************************
         * Add refence
         ********************************************************************************/
        PUMP_INLINE void add_refence() {
            ref_.fetch_add(1);
        }

        /*********************************************************************************
         * Sub refence
         ********************************************************************************/
        PUMP_INLINE void sub_refence() {
            if (ref_.fetch_sub(1) == 1) {
                INLINE_OBJECT_DELETE(this, io_buffer);
            }
        }

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        io_buffer() noexcept
          : size_(0), 
            read_pos_(0), 
            ref_(1) {
        }

        /*********************************************************************************
         * Copy constructor
         ********************************************************************************/
        io_buffer(const io_buffer&) = delete;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        virtual ~io_buffer() {
        }

        /*********************************************************************************
         * Assign operator
         ********************************************************************************/
        io_buffer& operator=(const io_buffer&) = delete;

      private:
        // Data size
        uint32_t size_;
        // Data read pos
        uint32_t read_pos_;
        // Refence count
        std::atomic_int ref_;
    };

}  // namespace toolkit
}  // namespace pump

#endif