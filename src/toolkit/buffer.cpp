// Import memcpy function
#include <string.h>

#include "pump/memory.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace toolkit {

    base_buffer::base_buffer() noexcept 
      : raw_(nullptr), 
        raw_size_(0) {
    }

    base_buffer::~base_buffer() {
        if (raw_ != nullptr) {
            pump_free(raw_);
        }
    }

    bool base_buffer::__init_by_allocate(uint32_t size) {
        try {
            if (raw_ == nullptr) {
                if ((raw_ = (block_t*)pump_malloc(size)) != nullptr) {
                    raw_size_ = size;
                    return true;
                }
            }
        } catch (const std::exception &) {
        }
        return false;
    }

    bool base_buffer::__init_by_copy(
        const block_t *b, 
        uint32_t size) {
        try {
            if (raw_ == nullptr && b != nullptr && size > 0) {
                if ((raw_ = (block_t*)pump_malloc(size)) != nullptr) {
                    memcpy(raw_, b, size);
                    raw_size_ = size;
                    return true;
                }
            }
        } catch (const std::exception &) {
        }
        return false;
    }

    bool base_buffer::__init_by_move(
        const block_t *b, 
        uint32_t size) {
        if (raw_ == nullptr && b != nullptr && size > 0) {
            raw_ = (block_t*)b;
            raw_size_ = size;
            return true;
        }
        return false;
    }

    bool io_buffer::append(
        const block_t *b, 
        uint32_t size) {
        if (b == nullptr || size == 0) {
            return false;
        }

        if (raw_ == nullptr) {
            return __init_by_copy(b, size);
        }

        if (read_pos_ == raw_size_) {
            reset();
        }

        uint32_t left = raw_size_ - read_pos_ - data_size_;
        if (size < left) {
            memcpy(raw_ + read_pos_ + data_size_, b, size);
            data_size_ += size;
        } else if (size + data_size_ < raw_size_) {
            memmove(raw_, raw_ + read_pos_, data_size_);
            memcpy(raw_ + data_size_, b, size);
            data_size_ += size;
            read_pos_ = 0;
        } else {
            uint32_t new_size_ = raw_size_ + size * 2;
            block_t *new_raw = (block_t*)pump_realloc(raw_, new_size_);
            if (new_raw == nullptr) {
                return false;
            }
            memcpy(raw_ + read_pos_ + data_size_, b, size);
            raw_size_ = new_size_;
            data_size_ += size;
        }

        return true;
    }

}  // namespace toolkit
}  // namespace pump
