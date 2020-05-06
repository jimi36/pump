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

#ifndef pump_transport_flow_buffer_h
#define pump_transport_flow_buffer_h

#include "pump/deps.h"

namespace pump {
	namespace transport {
		namespace flow {

			#define MAX_FLOW_BUFFER_SIZE 4096

			class LIB_PUMP buffer
			{
			public:
				/*********************************************************************************
				 * Constructor
				 ********************************************************************************/
				buffer() PUMP_NOEXCEPT : 
					rpos_(0)
				{}

				/*********************************************************************************
				 * Append
				 ********************************************************************************/
				bool append(c_block_ptr b, int32 size);

				/*********************************************************************************
				 * Reset
				 ********************************************************************************/
				PUMP_INLINE void reset()
				{ rpos_ = 0; raw_.clear(); }

				/*********************************************************************************
				 * Shift
				 ********************************************************************************/
				bool shift(int32 size);

				/*********************************************************************************
				 * Get buffer raw ptr
				 ********************************************************************************/
				PUMP_INLINE c_block_ptr raw() PUMP_CONST
				{ return raw_.empty() ? nullptr : (c_block_ptr)raw_.data(); }

				/*********************************************************************************
				 * Get buffer raw size
				 ********************************************************************************/
				PUMP_INLINE int32 raw_size() PUMP_CONST
				{  return (int32)raw_.size(); }

				/*********************************************************************************
				 * Get data ptr
				 ********************************************************************************/
				PUMP_INLINE c_block_ptr data() PUMP_CONST
				{ return raw_.empty() ? nullptr : raw_.data() + rpos_; }

				/*********************************************************************************
				 * Get data size
				 ********************************************************************************/
				PUMP_INLINE int32 data_size() PUMP_CONST
				{ return (int32)raw_.size() - rpos_; }

			private:
				int32 rpos_;
				std::string raw_;
			};
			DEFINE_ALL_POINTER_TYPE(buffer);

		}
	}
}

#endif