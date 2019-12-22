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

#ifndef librabbit_utils_buffer_h
#define librabbit_utils_buffer_h

#include "librabbit/deps.h"

namespace librabbit {
	namespace transport {
		namespace flow {

			#define MAX_FLOW_BUFFER_SIZE 4096

			class buffer
			{
			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				buffer();

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				~buffer();

				/*********************************************************************************
				 * Init
				 ********************************************************************************/
				bool init(c_block_ptr b, uint32 size);

				/*********************************************************************************
				 * Append
				 ********************************************************************************/
				bool append(c_block_ptr b, uint32 size);

				/*********************************************************************************
				 * Reset
				 ********************************************************************************/
				void reset();

				/*********************************************************************************
				 * Shift
				 ********************************************************************************/
				bool shift(uint32 size);

				/*********************************************************************************
				 * Get buffer ptr
				 ********************************************************************************/
				block_ptr ptr();

				/*********************************************************************************
				 * Get buffer size
				 ********************************************************************************/
				uint32 size() const { return (uint32)raw_.size(); }

				/*********************************************************************************
				 * Get data ptr
				 ********************************************************************************/
				c_block_ptr data();

				/*********************************************************************************
				 * Get data ptr
				 ********************************************************************************/
				uint32 data_size();

			private:
				std::string raw_;

				uint32 rpos_;
			};
			DEFINE_ALL_POINTER_TYPE(buffer);

		}
	}
}

#endif