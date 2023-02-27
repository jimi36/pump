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
    base_buffer(bool free) noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    virtual ~base_buffer();

    /*********************************************************************************
     * Get raw buffer pointer
     ********************************************************************************/
    pump_inline const char *raw() const noexcept {
        return raw_;
    }

    /*********************************************************************************
     * Get buffer capacity
     ********************************************************************************/
    pump_inline uint32_t capacity() const noexcept {
        return raw_size_;
    }

  protected:
    /*********************************************************************************
     * Init by allocate
     * Allocate a memory with the size.
     ********************************************************************************/
    bool __init_by_alloc(uint32_t size) noexcept;

    /*********************************************************************************
     * Init by copy
     * Allocate a memory block and copy input buffer to the buffer memory block.
     ********************************************************************************/
    bool __init_by_copy(const char *b, uint32_t size) noexcept;

    /*********************************************************************************
     * Init by reference
     ********************************************************************************/
    bool __init_by_reference(const char *b, uint32_t size) noexcept;

  protected:
    // Free flag
    bool free_;
    // Raw buffer
    char *raw_;
    // Raw buffer size
    uint32_t raw_size_;
};

class pump_lib io_buffer : public base_buffer {
  public:
    /*********************************************************************************
     * Create
     ********************************************************************************/
    static io_buffer *create(uint32_t size = 0) {
        pump_object_create_inline(obj, io_buffer, (true));
        if (size > 0 && obj != nullptr && !obj->__init_by_alloc(size)) {
            pump_object_destroy_inline(obj, io_buffer);
            return nullptr;
        }
        return obj;
    }
    static io_buffer *create_by_copy(const char *b, uint32_t size) {
        pump_object_create_inline(obj, io_buffer, (true));
        if (obj != nullptr && !obj->__init_by_copy(b, size)) {
            pump_object_destroy_inline(obj, io_buffer);
            return nullptr;
        }
        obj->size_ = size;
        return obj;
    }
    static io_buffer *create_by_refence(const char *b, uint32_t size) {
        pump_object_create_inline(obj, io_buffer, (false));
        if (obj != nullptr && !obj->__init_by_reference(b, size)) {
            obj->free_ = false;
            if (!obj->__init_by_reference(b, size)) {
                pump_object_destroy_inline(obj, io_buffer);
                return nullptr;
            }
        }
        obj->size_ = size;
        return obj;
    }

    /*********************************************************************************
     * Write bytes
     ********************************************************************************/
    bool write(const char *b, uint32_t size);

    /*********************************************************************************
     * Write bytes with the same byte
     ********************************************************************************/
    bool write(char b, uint32_t count = 1);

    /*********************************************************************************
     * Read bytes
     ********************************************************************************/
    bool read(char *b, uint32_t size);

    /*********************************************************************************
     * Read one byte
     ********************************************************************************/
    bool read(char *b);

    /*********************************************************************************
     * Shift data position.
     * If size > 0, shift to right.
     * If size < 0, shift to left.
     * If success return data size after shift, else return -1.
     ********************************************************************************/
    int32_t shift(int32_t size);

    /*********************************************************************************
     * Get data
     ********************************************************************************/
    pump_inline const char *data() const noexcept {
        if (size_ > 0) {
            return raw_ + rpos_;
        }
        return nullptr;
    }

    /*********************************************************************************
     * Get data size
     ********************************************************************************/
    pump_inline uint32_t size() const noexcept {
        return size_;
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
    pump_inline void clear() noexcept {
        size_ = 0;
        rpos_ = 0;
    }

    /*********************************************************************************
     * Reference
     ********************************************************************************/
    pump_inline void refer() noexcept {
        count_.fetch_add(1);
    }

    /*********************************************************************************
     * Free reference
     ********************************************************************************/
    pump_inline void unrefer() {
        if (count_.fetch_sub(1) == 1) {
            pump_object_destroy_inline(this, io_buffer);
        }
    }

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    io_buffer(bool free) noexcept
      : base_buffer(free),
        size_(0),
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