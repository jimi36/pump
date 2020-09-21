// Import "memcpy" on linux
#include <string.h>

#include "pump/memory.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace toolkit {

    base_buffer::base_buffer() noexcept : raw_(nullptr), raw_size_(0) {
    }

    base_buffer::~base_buffer() {
        if (raw_ != nullptr)
            pump_free(raw_);
    }

    bool base_buffer::__init_with_size(uint32 size) {
        try {
            if (raw_ == nullptr) {
                raw_ = (block_ptr)pump_malloc(size);
                if (raw_ != nullptr) {
                    raw_size_ = size;
                    return true;
                }
            }
        } catch (const std::exception &) {
        }

        return false;
    }

    bool base_buffer::__init_with_copy(c_block_ptr b, uint32 size) {
        try {
            if (raw_ == nullptr && b != nullptr && size > 0) {
                raw_ = (block_ptr)pump_malloc(size);
                if (raw_ != nullptr) {
                    raw_size_ = size;
                    memcpy(raw_, b, raw_size_);
                    return true;
                }
            }
        } catch (const std::exception &) {
        }

        return false;
    }

    bool base_buffer::__init_with_ownship(c_block_ptr b, uint32 size) {
        if (raw_ == nullptr && b != nullptr && size > 0) {
            raw_ = (block_ptr)b;
            raw_size_ = size;
            return true;
        }
        return false;
    }

    bool io_buffer::append(c_block_ptr b, uint32 size) {
        if (!b || size == 0)
            return false;

        if (raw_ == nullptr)
            return init_with_copy(b, size);

        if (read_pos_ == raw_size_)
            reset();

        uint32 left = raw_size_ - read_pos_ - data_size_;
        if (size < left) {
            memcpy(raw_ + read_pos_ + data_size_, b, size);
            data_size_ += size;
        } else if (size + data_size_ < raw_size_) {
            memcpy(raw_, raw_ + read_pos_, data_size_);
            memcpy(raw_ + data_size_, b, size);
            data_size_ += size;
            read_pos_ = 0;
        } else {
            uint32 new_size_ = raw_size_ + size * 2;
            raw_ = (block_ptr)pump_realloc(raw_, new_size_);
            if (raw_ == nullptr)
                return false;
            raw_size_ = new_size_;

            memcpy(raw_ + read_pos_ + data_size_, b, size);
            data_size_ += size;
        }

        return true;
    }

}  // namespace toolkit
}  // namespace pump
