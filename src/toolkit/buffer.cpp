// Import memcpy function
#include <string.h>

#include "pump/memory.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace toolkit {

base_buffer::base_buffer(bool alloced) noexcept
  : alloced_(alloced),
    raw_(nullptr),
    raw_size_(0) {
}

base_buffer::~base_buffer() {
    if (alloced_ && raw_ != nullptr) {
        pump_free(raw_);
    }
}

bool base_buffer::__init_by_alloc(uint32_t size) noexcept {
    pump_assert(size > 0);
    
    if (!alloced_ || raw_ != nullptr) {
        pump_abort();
    }

    try {
        if ((raw_ = (char *)pump_malloc(size)) == nullptr) {
            return true;
        }
    } catch (const std::exception &) {
        return false;
    }

    raw_size_ = size;

    return true;
}

bool base_buffer::__init_by_copy(const char *b, uint32_t size) noexcept {
    pump_assert(b != nullptr && size > 0);
    
    if (!alloced_ || raw_ != nullptr) {
        pump_abort();
    }

    try {
        if ((raw_ = (char *)pump_malloc(size)) == nullptr) {
            return false;
        }
    } catch (const std::exception &) {
        return false;
    }

    memcpy(raw_, b, size);
    raw_size_ = size;

    return true;
}

bool base_buffer::__init_by_reference(const char *b, uint32_t size) noexcept {
    if (alloced_ || raw_ != nullptr) {
        pump_abort();
    }
    if (b == nullptr && size > 0) {
        pump_abort();
    }

    raw_ = (char *)b;
    raw_size_ = size;

    return true;
}

io_buffer::io_buffer(bool free) noexcept
  : base_buffer(free),
    size_(0),
    rpos_(0),
    count_(1) {
}

bool io_buffer::write(const char *b, uint32_t size) {
    if (!alloced_) {
        pump_abort();
    }

    if (b == nullptr || size == 0) {
        return false;
    }

    if (raw_ == nullptr) {
        if (!__init_by_alloc(size)) {
            return false;
        }
    }

    if (rpos_ == raw_size_) {
        clear();
    }

    if (size > raw_size_ - rpos_ - size_) {
        if (size + size_ < raw_size_) {
            memmove(raw_, raw_ + rpos_, size_);
            rpos_ = 0;
        } else {
            char *new_raw = nullptr;
            auto new_size = (raw_size_ + size) / 2 * 3;
            try {
                new_raw = (char *)pump_realloc(raw_, new_size);
            } catch (const std::exception &) {
                if ((new_raw = (char *)pump_malloc(new_size)) != nullptr) {
                    memcpy(new_raw, raw_ + rpos_, size_);
                    pump_free(raw_);
                    rpos_ = 0;
                }
            }
            if (new_raw == nullptr) {
                return false;
            }
            raw_ = new_raw;
            raw_size_ = new_size;
        }
    }

    memcpy(raw_ + rpos_ + size_, b, size);

    size_ += size;

    return true;
}

bool io_buffer::write(char b, uint32_t count) {
    if (!alloced_) {
        pump_abort();
    }

    if (count == 0) {
        return false;
    }

    if (raw_ == nullptr) {
        if (!__init_by_alloc(count)) {
            return false;
        }
    } else {
        if (rpos_ == raw_size_) {
            clear();
        }

        if (count > raw_size_ - rpos_ - size_) {
            if (count + size_ < raw_size_) {
                memmove(raw_, raw_ + rpos_, size_);
                rpos_ = 0;
            } else {
                char *new_raw = nullptr;
                auto new_size = (raw_size_ + count) / 2 * 3;
                try {
                    new_raw = (char *)pump_realloc(raw_, new_size);
                } catch (const std::exception &) {
                    if ((new_raw = (char *)pump_malloc(new_size)) != nullptr) {
                        memcpy(new_raw, raw_ + rpos_, size_);
                        pump_free(raw_);
                        rpos_ = 0;
                    }
                }
                if (new_raw == nullptr) {
                    return false;
                }
                raw_ = new_raw;
                raw_size_ = new_size;
            }
        }
    }

    memset(raw_ + rpos_ + size_, b, count);

    size_ += count;

    return true;
}

bool io_buffer::read(char *b, uint32_t size) {
    if (size_ < size) {
        return false;
    }
    memcpy(b, raw_ + rpos_, size);
    rpos_ += size;
    size_ -= size;
    return true;
}

bool io_buffer::read(char *b) {
    if (size_ < 1) {
        return false;
    }
    *b = *(raw_ + rpos_);
    rpos_++;
    size_--;
    return true;
}

int32_t io_buffer::shift(int32_t size) {
    if (size > 0) {
        if (int32_t(size_) < size) {
            return -1;
        }
    } else {
        if (int32_t(rpos_) < -size) {
            return -1;
        }
    }
    rpos_ += size;
    size_ -= size;
    return size_;
}

bool io_buffer::reset_by_copy(const char *b, uint32_t size) {
    if (!alloced_) {
        pump_abort();
    }

    if (b == nullptr || size == 0) {
        return false;
    }

    clear();

    return write(b, size);
}

bool io_buffer::reset_by_reference(const char *b, uint32_t size) {
    if (alloced_) {
        pump_abort();
    }

    if (b == nullptr || size == 0) {
        return false;
    }

    clear();

    raw_ = (char *)b;
    raw_size_ = size;
    size_ = size;

    return true;
}

void io_buffer::clear() noexcept {
    size_ = 0;
    rpos_ = 0;
}

void io_buffer::refer() noexcept {
    count_.fetch_add(1);
}

void io_buffer::unrefer() {
    auto c = count_.fetch_sub(1);
    if (c == 1) {
        pump_object_destroy_inline(this, io_buffer);
    } else if (c <= 0) {
        pump_abort();
    }
}

}  // namespace toolkit
}  // namespace pump
