// Import memcpy function
#include <string.h>

#include "pump/memory.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace toolkit {

base_buffer::base_buffer() pump_noexcept
  : free_(true),
    raw_buffer_(nullptr),
    raw_size_(0) {
}

base_buffer::~base_buffer() {
    if (free_ && raw_buffer_ != nullptr) {
        pump_free(raw_buffer_);
    }
}

bool base_buffer::__init_by_alloc(uint32_t size) pump_noexcept {
    if (!free_ || raw_buffer_ != nullptr) {
        return false;
    }

    try {
        if (size == 0) {
            return true;
        }
        if ((raw_buffer_ = (char *)pump_malloc(size)) == nullptr) {
            return true;
        }
    } catch (const std::exception &) {
        return false;
    }

    raw_size_ = size;

    return true;
}

bool base_buffer::__init_by_copy(const char *b, uint32_t size) pump_noexcept {
    if (!free_ || raw_buffer_ != nullptr) {
        return false;
    }
    if (b == nullptr || size == 0) {
        return false;
    }

    try {
        if ((raw_buffer_ = (char *)pump_malloc(size)) == nullptr) {
            return false;
        }
    } catch (const std::exception &) {
        return false;
    }

    memcpy(raw_buffer_, b, size);
    raw_size_ = size;

    return true;
}

bool base_buffer::__init_by_reference(const char *b, uint32_t size) pump_noexcept {
    if (free_ || raw_buffer_ != nullptr) {
        return false;
    }
    if (b == nullptr || size == 0) {
        return false;
    }

    raw_buffer_ = (char *)b;
    raw_size_ = size;

    return true;
}

bool io_buffer::write(const char *b, uint32_t size) {
    if (!free_ || b == nullptr || size == 0) {
        return false;
    }

    if (raw_buffer_ == nullptr) {
        if (!__init_by_alloc(size)) {
            return false;
        }
    }

    if (rpos_ == raw_size_) {
        clear();
    }

    if (size > raw_size_ - rpos_ - size_) {
        if (size + size_ < raw_size_) {
            memmove(raw_buffer_, raw_buffer_ + rpos_, size_);
            rpos_ = 0;
        } else {
            char *new_raw = nullptr;
            uint32_t new_size = (raw_size_ + size) / 2 * 3;
            try {
                new_raw = (char *)pump_realloc(raw_buffer_, new_size);
            } catch (const std::exception &) {
                if ((new_raw = (char *)pump_malloc(new_size)) != nullptr) {
                    memcpy(new_raw, raw_buffer_ + rpos_, size_);
                    pump_free(raw_buffer_);
                    rpos_ = 0;
                }
            }
            if (new_raw == nullptr) {
                return false;
            }
            raw_buffer_ = new_raw;
            raw_size_ = new_size;
        }
    }

    memcpy(raw_buffer_ + rpos_ + size_, b, size);
    size_ += size;

    return true;
}

bool io_buffer::write(char b, uint32_t count) {
    if (!free_ || count == 0) {
        return false;
    }

    if (raw_buffer_ == nullptr) {
        if (!__init_by_alloc(count)) {
            return false;
        }
    } else {
        if (rpos_ == raw_size_) {
            clear();
        }

        if (count > raw_size_ - rpos_ - size_) {
            if (count + size_ < raw_size_) {
                memmove(raw_buffer_, raw_buffer_ + rpos_, size_);
                rpos_ = 0;
            } else {
                char *new_raw = nullptr;
                uint32_t new_size = (raw_size_ + count) / 2 * 3;
                try {
                    new_raw = (char *)pump_realloc(raw_buffer_, new_size);
                } catch (const std::exception &) {
                    if ((new_raw = (char *)pump_malloc(new_size)) != nullptr) {
                        memcpy(new_raw, raw_buffer_ + rpos_, size_);
                        pump_free(raw_buffer_);
                        rpos_ = 0;
                    }
                }
                if (new_raw == nullptr) {
                    return false;
                }
                raw_buffer_ = new_raw;
                raw_size_ = new_size;
            }
        }
    }

    memset(raw_buffer_ + rpos_ + size_, b, count);
    size_ += count;

    return true;
}

bool io_buffer::reset_by_copy(const char *b, uint32_t size) {
    if (b == nullptr || size == 0) {
        return false;
    }

    if (!free_) {
        raw_buffer_ = nullptr;
        raw_size_ = 0;
        free_ = true;
    }

    clear();

    return write(b, size);
}

bool io_buffer::reset_by_reference(const char *b, uint32_t size) {
    if (b == nullptr || size == 0) {
        return false;
    }

    if (free_ && raw_buffer_ != nullptr) {
        pump_free(raw_buffer_);
        free_ = false;
    }

    clear();

    raw_buffer_ = (char *)b;
    raw_size_ = size;
    size_ = size;

    return true;
}

}  // namespace toolkit
}  // namespace pump
