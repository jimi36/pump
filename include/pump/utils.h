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
#include <random>

#include "pump/types.h"

namespace pump {

/*********************************************************************************
 * Transform dec to hex.
 ********************************************************************************/
pump_lib char dec_to_hex(uint8_t dec);

/*********************************************************************************
 * Transform hex to dec.
 ********************************************************************************/
pump_lib uint8_t hex_to_dec(char hex);

/*********************************************************************************
 * Transform little and big endian.
 ********************************************************************************/
pump_lib uint16_t transform_endian_i16(uint16_t val);
pump_lib uint32_t transform_endian_i32(uint32_t val);
pump_lib uint64_t transform_endian_i64(uint64_t val);

/*********************************************************************************
 * Ceil to power of two.
 ********************************************************************************/
pump_lib int32_t ceil_to_power_of_two(int32_t val);

/*********************************************************************************
 * Random a value.
 ********************************************************************************/
pump_lib int32_t random();

/*********************************************************************************
 * Random a value between min and max.
 ********************************************************************************/
template <typename T> pump_lib T random(uint32_t seed, T min, T max) {
    std::default_random_engine e(seed);
    std::uniform_int_distribution<T> u(min, max);
    return u(e);
}

/*********************************************************************************
 * Random an array with value between min and max.
 ********************************************************************************/
template <typename T>
pump_lib std::vector<T> random(uint32_t seed, T min, T max, int32_t count) {
    std::vector<T> out(count, 0);
    std::default_random_engine e(seed);
    std::uniform_int_distribution<T> u(min, max);
    for (int32_t i = 0; i < count; i++) {
        out[i] = u(e);
    }
    return std::move(out);
}

/*********************************************************************************
 * Transform gbk to utf8 string
 ********************************************************************************/
pump_lib std::string gbk_to_utf8(const std::string &in);

/*********************************************************************************
 * Transform utf8 to gbk string
 ********************************************************************************/
pump_lib std::string utf8_to_gbk(const std::string &in);

/*********************************************************************************
 * Join strings
 ********************************************************************************/
pump_lib std::string join_strings(const std::vector<std::string> &src,
                                  const std::string &sep);

/*********************************************************************************
 * Split string
 ********************************************************************************/
pump_lib std::vector<std::string> split_string(const std::string &src,
                                               const std::string &sep);

}  // namespace pump

#endif