// Import memcpy function
#include <string.h>

#include "pump/memory.h"
#include "pump/toolkit/buffer.h"

namespace pump {
namespace toolkit {

base_buffer::base_buffer() noexcept :
    owner_(true),
    raw_(nullptr),
    raw_size_(0) {}

base_buffer::~base_buffer() {
    if (owner_ && raw_ != nullptr) {
        pump_free(raw_);
    }
}

bool base_buffer::__init_by_alloc(uint32_t size) {
    try {
        owner_ = true;
        if (raw_ == nullptr) {
            if (size == 0) {
                return true;
            } else if ((raw_ = (char *)pump_malloc(size)) != nullptr) {
                raw_size_ = size;
                return true;
            }
        }
    } catch (const std::exception &) {
    }
    return false;
}

bool base_buffer::__init_by_copy(const char *b, uint32_t size) {
    if (b == nullptr || size == 0) {
        return false;
    }
    try {
        if (raw_ == nullptr) {
            owner_ = true;
            if ((raw_ = (char *)pump_malloc(size)) != nullptr) {
                memcpy(raw_, b, size);
                raw_size_ = size;
                return true;
            }
        }
    } catch (const std::exception &) {
    }
    return false;
}

bool base_buffer::__init_by_reference(const char *b, uint32_t size) {
    if (raw_ == nullptr ||
        b == nullptr ||
        size == 0) {
        return false;
    }
    owner_ = false;
    raw_ = (char *)b;
    raw_size_ = size;
    return true;
}

bool io_buffer::write(const char *b, uint32_t size) {
    if (!owner_ || b == nullptr || size == 0) {
        return false;
    }

    if (raw_ == nullptr) {
        if (!__init_by_copy(b, size)) {
            return false;
        }
    } else {
        if (rpos_ == raw_size_) {
            clear();
        }

        if (size > raw_size_ - rpos_ - size_) {
            if (size + size_ < raw_size_) {
                memmove(raw_, raw_ + rpos_, size_);
                rpos_ = 0;
            } else {
                char *new_raw = nullptr;
                uint32_t new_size = (raw_size_ + size) / 2 * 3;
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
    }
    size_ += size;

    return true;
}

bool io_buffer::write(char b, uint32_t count) {
    if (!owner_ || count == 0) {
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
                uint32_t new_size = (raw_size_ + count) / 2 * 3;
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

bool io_buffer::reset_by_copy(const char *b, uint32_t size) {
    if (b == nullptr || size == 0) {
        return false;
    }

    clear();

    if (!owner_) {
        raw_size_ = 0;
        raw_ = nullptr;
    }
    owner_ = true;

    return write(b, size);
}

bool io_buffer::reset_by_reference(const char *b, uint32_t size) {
    if (b == nullptr || size == 0) {
        return false;
    }

    clear();

    if (owner_ && raw_ != nullptr) {
        pump_free(raw_);
    }
    owner_ = false;

    raw_ = (char *)b;
    raw_size_ = size;
    size_ = size;

    return true;
}

}  // namespace toolkit
}  // namespace pump
