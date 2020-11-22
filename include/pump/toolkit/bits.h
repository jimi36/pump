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
        bits_reader(c_uint8_ptr b, uint32 size) noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~bits_reader() = default;

        /*********************************************************************************
         * Read into integer
         ********************************************************************************/
        bool read(uint32 bc, uint8_ptr val);
        bool read(uint32 bc, uint16_ptr val);
        bool read(uint32 bc, uint32_ptr val);
        bool read(uint32 bc, uint64_ptr val);

        /*********************************************************************************
         * Get used bit count
         ********************************************************************************/
        PUMP_INLINE uint32 used_bc() const {
            return used_bc_;
        }

      private:
        /*********************************************************************************
         * Read one byte
         * Bit count has to be less than 8.
         ********************************************************************************/
        uint8 __read_from_byte(uint32 bc);

      private:
        // Left bit count
        uint32 left_bc_;
        // Used bit count
        uint32 used_bc_;
        // All bit count
        uint32 all_bc_;
        // Current byte pos
        c_uint8_ptr byte_pos_;
    };

    class LIB_PUMP bits_writer {

      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        bits_writer(uint8_ptr b, uint32 size) noexcept;

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~bits_writer() = default;

        /*********************************************************************************
         * Write integer
         ********************************************************************************/
        bool write(uint32 bc, uint8 val);
        bool write(uint32 bc, uint16 val);
        bool write(uint32 bc, uint32 val);
        bool write(uint32 bc, uint64 val);

        /*********************************************************************************
         * Get used bit count
         ********************************************************************************/
        PUMP_INLINE uint32 used_bc() const {
            return used_bc_;
        }

      private:
        /*********************************************************************************
         * Read one byte
         * Bit count has to be less than 8
         ********************************************************************************/
        void __write_to_byte(uint32 bc, uint8 val);

      private:
        // Left bit count
        uint32 left_bc_;
        // Used bit count
        uint32 used_bc_;
        // All bit count
        uint32 all_bc_;
        // Current byte pos
        uint8_ptr byte_pos_;
    };

}  // namespace toolkit
}  // namespace pump

#endif