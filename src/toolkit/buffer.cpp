// Import memcpy function
#include <string.h>

#include "pump/memory.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace toolkit {

    base_buffer::base_buffer() noexcept 
      : ref_(false),
        raw_(nullptr), 
        raw_size_(0) {
    }

    base_buffer::~base_buffer() {
        if (!ref_ && raw_ != nullptr) {
            pump_free(raw_);
        }
    }

    bool base_buffer::__init_by_alloc(uint32_t size) {
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

    bool base_buffer::__init_by_copy(const block_t *b, uint32_t size) {
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

    bool base_buffer::__init_by_move(const block_t *b, uint32_t size, bool ref) {
        if (raw_ == nullptr && b != nullptr && size > 0) {
            raw_ = (block_t*)b;
            raw_size_ = size;
            ref_ = ref;
            return true;
        }
        return false;
    }

    bool io_buffer::write(const block_t *b, uint32_t size) {
        try {
            if (b == nullptr || size == 0) {
                return false;
            }

            if (raw_ == nullptr) {
                if (!__init_by_copy(b, size)) {
                    return false;
                }
                size_ += size;
            } else {
                if (rpos_ == raw_size_) {
                    reset();
                }

                uint32_t left = raw_size_ - rpos_ - size_;
                if (size < left) {
                    memcpy(raw_ + rpos_ + size_, b, size);
                    size_ += size;
                } else if (size + size_ < raw_size_) {
                    memmove(raw_, raw_ + rpos_, size_);
                    memcpy(raw_ + size_, b, size);
                    size_ += size;
                    rpos_ = 0;
                } else {
                    uint32_t new_size_ = (raw_size_ + size) / 2 * 3;
                    block_t *new_raw = (block_t*)pump_realloc(raw_, new_size_);
                    if (new_raw == nullptr) {
                        return false;
                    }
                    memcpy(raw_ + rpos_ + size_, b, size);
                    raw_size_ = new_size_;
                    size_ += size;
                }
            }
        } catch (const std::exception &) {
            return false;
        }

        return true;
    }

    bool io_buffer::write(block_t b) {
        try {
            if (raw_ == nullptr) {
                if (!__init_by_alloc(4)) {
                    return false;
                }
            } else {
                if (rpos_ == raw_size_) {
                    reset();
                }

                uint32_t left = raw_size_ - rpos_ - size_;
                if (left == 0) {
                    if (size_ + 1 < raw_size_) {
                        memmove(raw_, raw_ + rpos_, size_);
                        rpos_ = 0;
                    } else {
                        uint32_t new_size_ = (raw_size_ + 1) / 2 * 3;
                        block_t *new_raw = (block_t*)pump_realloc(raw_, new_size_);
                        if (new_raw == nullptr) {
                            return false;
                        }
                        raw_size_ = new_size_;
                    }
                }

                raw_[rpos_ + size_] = b;
                size_ += 1;
            }
        } catch (const std::exception &) {
            return false;
        }

        return true;
    }

}  // namespace toolkit
}  // namespace pump
