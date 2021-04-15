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

#ifndef pump_utils_h
#define pump_utils_h

#include <string>
#include <vector>

#include "pump/types.h"

namespace pump {

    /*********************************************************************************
     * Transform dec number to hex char
     ********************************************************************************/
    LIB_PUMP uint8_t decnum_to_hexchar(uint8_t n);

    /*********************************************************************************
     * Transform hex char to dec number
     ********************************************************************************/
    LIB_PUMP uint8_t hexchar_to_decnum(uint8_t c);

    /*********************************************************************************
     * Change little endian and big endian
     ********************************************************************************/
    LIB_PUMP uint16_t change_endian(uint16_t val);
    LIB_PUMP uint32_t change_endian(uint32_t val);

    /*********************************************************************************
     * Ceil to pow of 2
     ********************************************************************************/
    LIB_PUMP int32_t ceil_to_pow2(int32_t x);

    /*********************************************************************************
     * Transform gbk to utf8
     ********************************************************************************/
    LIB_PUMP std::string gbk_to_utf8(const std::string &in);

    /*********************************************************************************
     * Transform utf8 to gbk
     ********************************************************************************/
    LIB_PUMP std::string utf8_to_gbk(const std::string &in);

    /*********************************************************************************
     * Join strings
     ********************************************************************************/
    LIB_PUMP std::string join_strings(
        const std::vector<std::string> &src,
        const std::string &sep);

    /*********************************************************************************
     * Split string
     ********************************************************************************/
    LIB_PUMP std::vector<std::string> split_string(
        const std::string &src,
        const std::string &sep);

}  // namespace pump

#endif