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
#include <string>

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
        bool __init_by_alloc(uint32_t size);

        /*********************************************************************************
         * Init by copy
         * Allocate a memory block and copy input buffer to the buffer memory block.
         ********************************************************************************/
        bool __init_by_copy(const block_t *b, uint32_t size);

        /*********************************************************************************
         * Init by move
         * The input buffer will be moved to the buffer.
         ********************************************************************************/
        bool __init_by_move(const block_t *b, uint32_t size, bool buf_ref);
        
      protected:
        // Buffer ref flag
        bool buf_ref_;
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
        static io_buffer* create(uint32_t size = 0) {
            INLINE_OBJECT_CREATE(obj, io_buffer, ())
            if (obj != nullptr && size > 0 && !obj->__init_by_alloc(size)) {
                INLINE_OBJECT_DELETE(obj, io_buffer)
                return nullptr;
            }
            return obj;
        }
        static io_buffer* create_by_copy(const block_t *b, uint32_t size) {
            INLINE_OBJECT_CREATE(obj, io_buffer, ())
            if (obj != nullptr && !obj->__init_by_copy(b, size)) {
                INLINE_OBJECT_DELETE(obj, io_buffer)
                return nullptr;
            }

            obj->size_ = size;

            return obj;
        }
        static io_buffer* create_by_move(const block_t *b, uint32_t size) {
            INLINE_OBJECT_CREATE(obj, io_buffer, ())
            if (obj != nullptr) {
                if (b != nullptr && size > 0) {
                    if (!obj->__init_by_move(b, size, false)) {
                        INLINE_OBJECT_DELETE(obj, io_buffer)
                        return nullptr;
                    }
                    obj->size_ = size;
                }
            }
            return obj;
        }
        static io_buffer* create_by_refence(const block_t *b, uint32_t size) {
            INLINE_OBJECT_CREATE(obj, io_buffer, ())
            if (obj != nullptr) {
                if (b != nullptr && size > 0) {
                    if (!obj->__init_by_move(b, size, true)) {
                        INLINE_OBJECT_DELETE(obj, io_buffer)
                        return nullptr;
                    }
                    obj->size_ = size;
                } else {
                    obj->buf_ref_ = true;
                }
            }
            return obj;
        }

        /*********************************************************************************
         * Write block
         ********************************************************************************/
        bool write(const block_t *b, uint32_t size);
        bool write(block_t b);

        /*********************************************************************************
         * Read block
         ********************************************************************************/
        PUMP_INLINE bool read(block_t *b, uint32_t size) {
            if (size_ < size) {
                return false;
            }
            memcpy(b, raw_ + rpos_, size);
            rpos_ += size;
            size_ -= size;
            return true;
        }
        PUMP_INLINE bool read(block_t *b) {
            if (size_ < 1) {
                return false;
            }
            *b = *(raw_ + rpos_);
            rpos_++;
            size_--;
            return true;
        }

        /*********************************************************************************
         * Shift
         * If success return current size, else return zero.
         ********************************************************************************/
        PUMP_INLINE int32_t shift(int32_t size) {
            PUMP_ASSERT(int32_t(size_) >= size);
            if (size_ == 0 || int32_t(size_) < size) {
                return -1;
            }
            rpos_ += size;
            size_ -= size;
            return size_;
        }

        /*********************************************************************************
         * Get data
         ********************************************************************************/
        PUMP_INLINE const block_t *data() const {
            if (size_ > 0) {
                return raw_ + rpos_;
            }
            return nullptr;
        }

        /*********************************************************************************
         * Get data size
         ********************************************************************************/
        PUMP_INLINE uint32_t size() const {
            return size_;
        }

        /*********************************************************************************
         * Get string
         ********************************************************************************/
        PUMP_INLINE std::string string() const {
            if (raw_ == nullptr || size_ == 0) {
                return std::string();
            }
            return std::string(raw_ + rpos_, size_);
        }

        /*********************************************************************************
         * Reset with buffer
         * Only io buffer with buffer refence mode can reset with buffer. 
         ********************************************************************************/
        bool reset(const block_t *b, uint32_t size);

        /*********************************************************************************
         * Reset
         ********************************************************************************/
        PUMP_INLINE void reset() {
            size_ = rpos_ = 0;
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
            rpos_(0), 
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
        uint32_t rpos_;
        // Refence count
        std::atomic_int ref_;
    };

}  // namespace toolkit
}  // namespace pump

#endif