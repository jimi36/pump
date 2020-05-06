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

#ifndef pump_utils_strings_h
#define pump_utils_strings_h

#include "pump/deps.h"

namespace pump {
	namespace utils {

		/*********************************************************************************
		 * Transform gbk to utf8
		 ********************************************************************************/
		LIB_PUMP bool gbk_to_utf8(const std::string &src, std::string &des);

		/*********************************************************************************
		 * Transform utf8 to gbk
		 ********************************************************************************/
		LIB_PUMP bool utf8_to_gbk(const std::string &src, std::string &des);

		/*********************************************************************************
		 * Join strings
		 ********************************************************************************/
		LIB_PUMP std::string join_strings(
			const std::vector<std::string> &srcs, 
			const std::string &sep
		);

		/*********************************************************************************
		 * Split string
		 ********************************************************************************/
		LIB_PUMP void split_string(
			const std::string &src, 
			const std::string &sep, 
			std::vector<std::string> &rets
		);

	}
}

#endif