#include "pump/toolkit/bits.h"

namespace pump {
namespace toolkit {

bits_reader::bits_reader(const uint8_t *b, uint32_t size) noexcept :
    unread_bc_(size * 8), read_bc_(0), byte_left_bc_(8), byte_pos_(b) {
    PUMP_ASSERT(b);
    PUMP_ASSERT(size > 0);
}

bool bits_reader::read(uint32_t bc, uint8_t *val) {
    if (bc > 8 || bc > unread_bc_) {
        return false;
    }

    *val = __read_from_byte(bc);

    return true;
}

bool bits_reader::read(uint32_t bc, uint16_t *val) {
    if (bc > 16 || bc > unread_bc_) {
        return false;
    }

#if defined(LITTLE_ENDIAN)
    int32_t idx = (bc + 7) / 8 - 1;
    int32_t s = -1;
#elif defined(BIG_ENDIAN)
    int32_t idx = 0;
    int32_t s = 1;
#endif
    uint32_t rc = bc % 8;
    if (rc == 0) {
        rc = 8;
    }

    for (; bc > 0; bc -= rc, rc = 8, idx += s) {
        *((uint8_t *)val + idx) = __read_from_byte(rc);
    }

    return true;
}

bool bits_reader::read(uint32_t bc, uint32_t *val) {
    if (bc > 32 || bc > unread_bc_) {
        return false;
    }

#if defined(LITTLE_ENDIAN)
    int32_t idx = (bc + 7) / 8 - 1;
    int32_t s = -1;
#elif defined(BIG_ENDIAN)
    int32_t idx = 0;
    int32_t s = 1;
#endif
    uint32_t rc = bc % 8;
    if (rc == 0) {
        rc = 8;
    }

    for (; bc > 0; bc -= rc, rc = 8, idx += s) {
        *((uint8_t *)val + idx) = __read_from_byte(rc);
    }

    return true;
}

bool bits_reader::read(uint32_t bc, uint64_t *val) {
    if (bc > 64 || bc > unread_bc_) {
        return false;
    }

#if defined(LITTLE_ENDIAN)
    int32_t idx = (bc + 7) / 8 - 1;
    int32_t s = -1;
#elif defined(BIG_ENDIAN)
    int32_t idx = 0;
    int32_t s = 1;
#endif
    uint32_t rc = bc % 8;
    if (rc == 0) {
        rc = 8;
    }

    for (; bc > 0; bc -= rc, rc = 8, idx += s) {
        *((uint8_t *)val + idx) = __read_from_byte(rc);
    }

    return true;
}

uint8_t bits_reader::__read_from_byte(uint32_t bc) {
    uint8_t val = 0;
    while (bc > 0) {
        uint8_t rc = byte_left_bc_ > bc ? bc : byte_left_bc_;
        val = (val << rc) | (uint8_t((*byte_pos_) << (8 - byte_left_bc_)) >> (8 - rc));

        if ((byte_left_bc_ -= rc) == 0) {
            byte_left_bc_ = 8;
            byte_pos_++;
        }

        unread_bc_ -= rc;
        read_bc_ += rc;
        bc -= rc;
    }
    return val;
}

bits_writer::bits_writer(uint8_t *b, uint32_t size) noexcept :
    unwritten_bc_(size * 8), written_bc_(0), byte_left_bc_(8), byte_pos_(b) {
    PUMP_ASSERT(b);
    PUMP_ASSERT(size > 0);
}

bool bits_writer::write(uint32_t bc, uint8_t val) {
    if (bc > 8 || bc > unwritten_bc_) {
        return false;
    }

    __write_to_byte(bc, val);

    return true;
}

bool bits_writer::write(uint32_t bc, uint16_t val) {
    if (bc > 16 || bc > unwritten_bc_) {
        return false;
    }

#if defined(LITTLE_ENDIAN)
    int32_t idx = (bc + 7) / 8 - 1;
    int32_t s = -1;
#elif defined(BIG_ENDIAN)
    int32_t idx = 0;
    int32_t s = 1;
#endif
    uint32_t rc = bc % 8;
    if (rc == 0) {
        rc = 8;
    }

    for (; bc > 0; bc -= rc, rc = 8, idx += s) {
        __write_to_byte(rc, *((uint8_t *)&val + idx));
    }

    return true;
}

bool bits_writer::write(uint32_t bc, uint32_t val) {
    if (bc > 32 || bc > unwritten_bc_) {
        return false;
    }

#if defined(LITTLE_ENDIAN)
    int32_t idx = (bc + 7) / 8 - 1;
    int32_t s = -1;
#elif defined(BIG_ENDIAN)
    int32_t idx = 0;
    int32_t s = 1;
#endif
    uint32_t rc = bc % 8;
    if (rc == 0) {
        rc = 8;
    }

    for (; bc > 0; bc -= rc, rc = 8, idx += s) {
        __write_to_byte(rc, *((uint8_t *)&val + idx));
    }

    return true;
}

bool bits_writer::write(uint32_t bc, uint64_t val) {
    if (bc > 64 || bc > unwritten_bc_) {
        return false;
    }

#if defined(LITTLE_ENDIAN)
    int32_t idx = (bc + 7) / 8 - 1;
    int32_t s = -1;
#elif defined(BIG_ENDIAN)
    int32_t idx = 0;
    int32_t s = 1;
#endif
    uint32_t rc = bc % 8;
    if (rc == 0) {
        rc = 8;
    }

    for (; bc > 0; bc -= rc, rc = 8, idx += s) {
        __write_to_byte(rc, *((uint8_t *)&val + idx));
    }

    return true;
}

void bits_writer::__write_to_byte(uint32_t bc, uint8_t val) {
    if (byte_left_bc_ < bc) {
        *byte_pos_ |= ((val & (0xff >> (8 - byte_left_bc_))) >> (bc - byte_left_bc_));
        unwritten_bc_ -= byte_left_bc_;
        written_bc_ += byte_left_bc_;
        bc -= byte_left_bc_;

        byte_left_bc_ = 8;
        byte_pos_++;
    }

    *byte_pos_ |= ((val & (0xff >> (8 - bc))) << (byte_left_bc_ - bc));
    unwritten_bc_ -= bc;
    written_bc_ += bc;

    if ((byte_left_bc_ -= bc) == 0) {
        byte_left_bc_ = 8;
        byte_pos_++;
    }
}

}  // namespace toolkit
}  // namespace pump
