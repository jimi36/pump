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
         * Get buffer raw ptr
         ********************************************************************************/
        PUMP_INLINE const block_t* buffer() const {
            return raw_;
        }

        /*********************************************************************************
         * Get buffer raw size
         ********************************************************************************/
        PUMP_INLINE uint32_t buffer_size() const {
            return raw_size_;
        }

      protected:
        /*********************************************************************************
         * Init with size
         * Allocate a memory block with the size.
         ********************************************************************************/
        bool __init_with_size(uint32_t size);

        /*********************************************************************************
         * Init with copy
         * Allocate a memory block and copy input buffer to the buffer memory block.
         ********************************************************************************/
        bool __init_with_copy(const block_t *b, uint32_t size);

        /*********************************************************************************
         * Init with ownership
         * The input buffer ownership transfer to the buffer.
         ********************************************************************************/
        bool __init_with_ownership(const block_t *b, uint32_t size);

        /*********************************************************************************
         * Append
         * Append input buffer by copying. If there is no enough memory block to use, the
         * buffer will allocate a new memory block.
         ********************************************************************************/
        // bool __append(c_block_ptr b, uint32 size);

      protected:
        // Raw buffer
        block_t *raw_;
        // Raw buffer size
        uint32_t raw_size_;
    };

    class io_buffer;
    DEFINE_RAW_POINTER_TYPE(io_buffer);

    class io_buffer
      : public base_buffer {

      public:
        /*********************************************************************************
         * Create
         ********************************************************************************/
        static io_buffer_ptr create() {
            INLINE_OBJECT_CREATE(obj, io_buffer, ());
            return obj;
        }

        /*********************************************************************************
         * Init with size
         * Allocate a memory block with the size.
         ********************************************************************************/
        PUMP_INLINE bool init_with_size(uint32_t size) {
            return __init_with_size(size);
        }

        /*********************************************************************************
         * Init with copy
         * Allocate a memory block and copy input buffer to the buffer memory block.
         ********************************************************************************/
        PUMP_INLINE bool init_with_copy(const block_t *b, uint32_t size) {
            if (__init_with_copy(b, size)) {
                data_size_ = size;
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Init with ownership
         * The input buffer ownership transfer to the buffer.
         * The input buffer must be created by pump_malloc or pump_realloc.
         ********************************************************************************/
        PUMP_INLINE bool init_with_ownership(const block_t *b, uint32_t size) {
            if (__init_with_ownership(b, size)) {
                data_size_ = size;
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Append
         * Append input buffer by copying. If there is no enough memory block to use, the
         * buffer will allocate a new memory block.
         ********************************************************************************/
        bool append(const block_t *b, uint32_t size);

        /*********************************************************************************
         * Shift
         * Return data size.
         ********************************************************************************/
        PUMP_INLINE uint32_t shift(uint32_t size) {
            PUMP_ASSERT(data_size_ >= size);
            read_pos_ += size;
            data_size_ -= size;
            return data_size_;
        }

        /*********************************************************************************
         * Get data
         ********************************************************************************/
        PUMP_INLINE const block_t *data() const {
            return data_size_ == 0 ? nullptr : (raw_ + read_pos_);
        }

        /*********************************************************************************
         * Get data size
         ********************************************************************************/
        PUMP_INLINE uint32_t data_size() const {
            return data_size_;
        }

        /*********************************************************************************
         * Reset data size
         ********************************************************************************/
        PUMP_INLINE bool reset_data_size(uint32_t size) {
            if (PUMP_LIKELY(size <= raw_size_)) {
                data_size_ = size;
                read_pos_ = 0;
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Add data size
         ********************************************************************************/
        PUMP_INLINE bool add_data_size(uint32_t size) {
            if (PUMP_LIKELY(read_pos_ + data_size_ + size <= raw_size_)) {
                data_size_ += size;
                return true;
            }
            return false;
        }

        /*********************************************************************************
         * Reset
         ********************************************************************************/
        PUMP_INLINE void reset() {
            read_pos_ = data_size_ = 0;
        }

        /*********************************************************************************
         * Add ref
         ********************************************************************************/
        PUMP_INLINE void add_ref() {
            ref_cnt_.fetch_add(1);
        }

        /*********************************************************************************
         * Sub ref
         ********************************************************************************/
        PUMP_INLINE void sub_ref() {
            if (ref_cnt_.fetch_sub(1) == 1) {
                INLINE_OBJECT_DELETE(this, io_buffer);
            }
        }

      private:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        io_buffer() noexcept
          : data_size_(0), 
            read_pos_(0), 
            ref_cnt_(1) {
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
        // data size
        uint32_t data_size_;
        // data read pos
        uint32_t read_pos_;

        // Ref count
        std::atomic_int ref_cnt_;
    };

}  // namespace toolkit
}  // namespace pump

#endif