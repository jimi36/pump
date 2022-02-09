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

#ifndef pump_toolkit_bits_h
#define pump_toolkit_bits_h

#include "pump/debug.h"
#include "pump/types.h"
#include "pump/platform.h"

namespace pump {
namespace toolkit {

class LIB_PUMP bits_reader {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    bits_reader(const uint8_t *b, uint32_t size) noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~bits_reader() = default;

    /*********************************************************************************
     * Read into integer
     ********************************************************************************/
    bool read(uint32_t bc, uint8_t *val);
    bool read(uint32_t bc, uint16_t *val);
    bool read(uint32_t bc, uint32_t *val);
    bool read(uint32_t bc, uint64_t *val);

    /*********************************************************************************
     * Get read bit count
     ********************************************************************************/
    PUMP_INLINE uint32_t read_bc() const {
        return read_bc_;
    }

  private:
    /*********************************************************************************
     * Read one byte
     * Bit count has to be less than 8.
     ********************************************************************************/
    uint8_t __read_from_byte(uint32_t bc);

  private:
    // Unread bit count
    uint32_t unread_bc_;
    // Read bit count
    uint32_t read_bc_;
    // Byte left bit count
    uint32_t byte_left_bc_;
    // Current byte pos
    const uint8_t *byte_pos_;
};

class LIB_PUMP bits_writer {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    bits_writer(uint8_t *b, uint32_t size) noexcept;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~bits_writer() = default;

    /*********************************************************************************
     * Write integer
     ********************************************************************************/
    bool write(uint32_t bc, uint8_t val);
    bool write(uint32_t bc, uint16_t val);
    bool write(uint32_t bc, uint32_t val);
    bool write(uint32_t bc, uint64_t val);

    /*********************************************************************************
     * Get written bit count
     ********************************************************************************/
    PUMP_INLINE uint32_t written_bc() const {
        return written_bc_;
    }

  private:
    /*********************************************************************************
     * Read one byte
     * Bit count has to be less than 8
     ********************************************************************************/
    void __write_to_byte(uint32_t bc, uint8_t val);

  private:
    // Unwritten bit count
    uint32_t unwritten_bc_;
    // Written bit count
    uint32_t written_bc_;
    // Left bit count
    uint32_t byte_left_bc_;
    // Current byte pos
    uint8_t *byte_pos_;
};

}  // namespace toolkit
}  // namespace pump

#endif