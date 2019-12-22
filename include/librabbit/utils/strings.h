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

#ifndef librabbit_utils_strings_h
#define librabbit_utils_strings_h

#include "librabbit/deps.h"

namespace librabbit {
	namespace utils {

		/*********************************************************************************
		 * Transform dec number to hex char
		 ********************************************************************************/
		LIB_EXPORT uint8 dec_to_hexchar(uint8 n);

		/*********************************************************************************
		 * Transform hex char to dec number
		 ********************************************************************************/
		LIB_EXPORT uint8 hexchar_to_dec(uint8 c);

		/*********************************************************************************
		 * Transform gbk to utf8
		 ********************************************************************************/
		LIB_EXPORT bool gbk_to_utf8(const std::string &src, std::string &des);

		/*********************************************************************************
		 * Transform utf8 to gbk
		 ********************************************************************************/
		LIB_EXPORT bool utf8_to_gbk(const std::string &src, std::string &des);

		/*********************************************************************************
		 * Find substring postion in string
		 ********************************************************************************/
		LIB_EXPORT const int8* find_sub_string(const int8 *str1, const int8 *str2, int32 max_len);

	}
}

#endif