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
    base_buffer(bool alloced) noexcept;

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

    /*********************************************************************************
     * Check raw buffer alloced or not
     ********************************************************************************/
    pump_inline bool is_alloced() const noexcept {
        return alloced_;
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
    // Alloced flag
    bool alloced_;

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
        pump_object_create_inline(io_buffer, obj, true);
        if (obj != nullptr) {
            if (size > 0 && !obj->__init_by_alloc(size)) {
                pump_object_destroy_inline(obj, io_buffer);
                return nullptr;
            }
        }
        return obj;
    }
    static io_buffer *create_by_copy(const char *b = nullptr, uint32_t size = 0) {
        pump_object_create_inline(io_buffer, obj, true);
        if (obj != nullptr) {
            if (b != nullptr && size > 0) {
                if (!obj->__init_by_copy(b, size)) {
                    pump_object_destroy_inline(obj, io_buffer);
                    return nullptr;
                }
                obj->size_ = size;
            }
        }
        return obj;
    }
    static io_buffer *create_by_reference(const char *b = nullptr, uint32_t size = 0) {
        pump_object_create_inline(io_buffer, obj, false);
        if (obj != nullptr) {
            if (b != nullptr && size > 0) {
                if (!obj->__init_by_reference(b, size)) {
                    pump_object_destroy_inline(obj, io_buffer);
                    return nullptr;
                }
                obj->size_ = size;
            }
        }
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
     * Clear data
     ********************************************************************************/
    void clear() noexcept;

    /*********************************************************************************
     * Reference
     ********************************************************************************/
    void refer() noexcept;

    /*********************************************************************************
     * Free reference
     ********************************************************************************/
    void unrefer();

  private:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    io_buffer(bool free) noexcept;

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

class shared_buffer {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    shared_buffer()
      : iob_(nullptr) {
    }
    shared_buffer(io_buffer *iob)
      : iob_(iob) {
    }
    shared_buffer(const shared_buffer &b)
      : iob_(b.iob_) {
        if (iob_ != nullptr) {
            iob_->refer();
        }
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~shared_buffer() {
        if (iob_ != nullptr) {
            iob_->unrefer();
        }
    }

    /*********************************************************************************
     * Assign operator
     ********************************************************************************/
    shared_buffer& operator=(const shared_buffer &b) {
        if (this == &b || iob_ == b.iob_) {
            return *this;
        }
        if (iob_ != nullptr) {
            iob_->unrefer();
        }
        iob_ = b.iob_;
        if (iob_ != nullptr) {
            iob_->refer();
        }
        return *this;
    }
    shared_buffer &operator=(io_buffer *iob) {
        if (iob_ == iob) {
            return *this;
        }
        if (iob_ != nullptr) {
            iob_->unrefer();
        }
        iob_ = iob;
        if (iob_ != nullptr) {
            iob_->refer();
        }
        return *this;
    }
	
	/*********************************************************************************
     * Bool operator
     ********************************************************************************/
    operator bool() const noexcept {
        return iob_ != nullptr;
    }
	
	/*********************************************************************************
     * Get io buffer
     ********************************************************************************/
    pump_inline io_buffer* get_io_buffer() {
        return iob_;
    }

    /*********************************************************************************
     * Write bytes
     ********************************************************************************/
    pump_inline bool write(const char *b, uint32_t size) {
        if (iob_ != nullptr) {
            return iob_->write(b, size);
        }
        return false;
    }

    /*********************************************************************************
     * Write bytes with the same byte
     ********************************************************************************/
    pump_inline bool write(char b, uint32_t count = 1) {
        if (iob_ != nullptr) {
            return iob_->write(b, count);
        }
        return false;
    }

    /*********************************************************************************
     * Read bytes
     ********************************************************************************/
    pump_inline bool read(char *b, uint32_t size) {
        if (iob_ != nullptr) {
            return iob_->read(b, size);
        }
        return false;
    }

    /*********************************************************************************
     * Read one byte
     ********************************************************************************/
    pump_inline bool read(char *b) {
        if (iob_ != nullptr) {
            return iob_->read(b);
        }
        return false;
    }

    /*********************************************************************************
     * Shift data position.
     * If size > 0, shift to right.
     * If size < 0, shift to left.
     * If success return data size after shift, else return -1.
     ********************************************************************************/
    pump_inline int32_t shift(int32_t size) {
        if (iob_ != nullptr) {
            return iob_->shift(size);
        }
        return -1;
    }

    /*********************************************************************************
     * Get data
     ********************************************************************************/
    pump_inline const char *data() const noexcept {
        if (iob_ != nullptr) {
            return iob_->data();
        }
        return nullptr;
    }

    /*********************************************************************************
     * Get data size
     ********************************************************************************/
    pump_inline uint32_t size() const noexcept {
        if (iob_ != nullptr) {
            return iob_->size();
        }
        return 0;
    }
  
  private:
    io_buffer *iob_;
};

}  // namespace toolkit
}  // namespace pump

#endif