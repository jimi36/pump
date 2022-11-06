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

#include <pump/debug.h>
#include <pump/types.h>
#include <pump/memory.h>
#include <pump/platform.h>

namespace pump {
namespace toolkit {

class pump_lib base_buffer {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    base_buffer() pump_noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~base_buffer();

    /*********************************************************************************
     * Get raw buffer pointer
     ********************************************************************************/
    pump_inline const char *raw() const pump_noexcept {
        return raw_buffer_;
    }

    /*********************************************************************************
     * Get buffer capacity
     ********************************************************************************/
    pump_inline uint32_t capacity() const pump_noexcept {
        return raw_size_;
    }

  protected:
    /*********************************************************************************
     * Init by allocate
     * Allocate a memory with the size.
     ********************************************************************************/
    bool __init_by_alloc(uint32_t size) pump_noexcept;

    /*********************************************************************************
     * Init by copy
     * Allocate a memory block and copy input buffer to the buffer memory block.
     ********************************************************************************/
    bool __init_by_copy(const char *b, uint32_t size) pump_noexcept;

    /*********************************************************************************
     * Init by reference
     ********************************************************************************/
    bool __init_by_reference(const char *b, uint32_t size) pump_noexcept;

  protected:
    // Free flag
    bool free_;
    // Raw buffer
    char *raw_buffer_;
    // Raw buffer size
    uint32_t raw_size_;
};

class pump_lib io_buffer : public base_buffer {
  public:
    /*********************************************************************************
     * Create
     ********************************************************************************/
    static io_buffer *create(uint32_t size = 0) {
        INLINE_OBJECT_CREATE(obj, io_buffer, ())
        if (obj != nullptr && !obj->__init_by_alloc(size)) {
            INLINE_OBJECT_DELETE(obj, io_buffer)
            return nullptr;
        }
        return obj;
    }
    static io_buffer *create_by_copy(const char *b, uint32_t size) {
        INLINE_OBJECT_CREATE(obj, io_buffer, ())
        if (obj != nullptr && !obj->__init_by_copy(b, size)) {
            INLINE_OBJECT_DELETE(obj, io_buffer)
            return nullptr;
        }
        obj->size_ = size;
        return obj;
    }
    static io_buffer *create_by_refence(const char *b, uint32_t size) {
        INLINE_OBJECT_CREATE(obj, io_buffer, ())
        if (obj != nullptr && !obj->__init_by_reference(b, size)) {
            obj->free_ = false;
            if (!obj->__init_by_reference(b, size)) {
                INLINE_OBJECT_DELETE(obj, io_buffer)
                return nullptr;
            }
        }
        obj->size_ = size;
        return obj;
    }

    /*********************************************************************************
     * Write block
     ********************************************************************************/
    bool write(const char *b, uint32_t size);
    bool write(char b, uint32_t count);

    /*********************************************************************************
     * Read block
     ********************************************************************************/
    pump_inline bool read(char *b, uint32_t size) {
        if (size_ < size) {
            return false;
        }
        memcpy(b, raw_buffer_ + rpos_, size);
        rpos_ += size;
        size_ -= size;
        return true;
    }
    pump_inline bool read(char *b) {
        if (size_ < 1) {
            return false;
        }
        *b = *(raw_buffer_ + rpos_);
        rpos_++;
        size_--;
        return true;
    }

    /*********************************************************************************
     * Shift
     * If success return current size, else return -1.
     ********************************************************************************/
    pump_inline int32_t shift(int32_t size) {
        pump_assert(int32_t(size_) >= size);
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
    pump_inline const char *data() const pump_noexcept {
        if (size_ > 0) {
            return raw_buffer_ + rpos_;
        }
        return nullptr;
    }

    /*********************************************************************************
     * Get data size
     ********************************************************************************/
    pump_inline uint32_t size() const pump_noexcept {
        return size_;
    }

    /*********************************************************************************
     * Get string
     ********************************************************************************/
    pump_inline std::string string() const {
        if (raw_buffer_ == nullptr || size_ == 0) {
            return std::string();
        }
        return std::string(raw_buffer_ + rpos_, size_);
    }

    /*********************************************************************************
     * Reset by copy
     ********************************************************************************/
    bool reset_by_copy(const char *b, uint32_t size);

    /*********************************************************************************
     * Reset by reference
     ********************************************************************************/
    bool reset_by_reference(const char *b, uint32_t size);

    /*********************************************************************************
     * Clear
     ********************************************************************************/
    pump_inline void clear() pump_noexcept {
        size_ = 0;
        rpos_ = 0;
    }

    /*********************************************************************************
     * Reference
     ********************************************************************************/
    pump_inline void refer() pump_noexcept {
        count_.fetch_add(1);
    }

    /*********************************************************************************
     * Free reference
     ********************************************************************************/
    pump_inline void unrefer() {
        if (count_.fetch_sub(1) == 1) {
            INLINE_OBJECT_DELETE(this, io_buffer);
        }
    }

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    io_buffer() pump_noexcept
      : size_(0),
        rpos_(0),
        count_(1) {
    }

    /*********************************************************************************
     * Copy constructor
     ********************************************************************************/
    io_buffer(const io_buffer &) = delete;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~io_buffer() = default;

    /*********************************************************************************
     * Assign operator
     ********************************************************************************/
    io_buffer &operator=(const io_buffer &) = delete;

  private:
    // Data size
    uint32_t size_;
    // Data read pos
    uint32_t rpos_;
    // Reference count
    std::atomic_int count_;
};

}  // namespace toolkit
}  // namespace pump

#endif