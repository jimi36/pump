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

#include "pump/headers.h"

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
				buffer() noexcept;

				/*********************************************************************************
				 * Deconstructor
				 ********************************************************************************/
				~buffer();

				/*********************************************************************************
				 * Append
				 ********************************************************************************/
				bool append(c_block_ptr b, uint32 size);

				/*********************************************************************************
				 * Reset
				 ********************************************************************************/
				PUMP_INLINE void reset()
				{ data_pos_ = data_size_ = 0; }

				/*********************************************************************************
				 * Shift
				 ********************************************************************************/
				bool shift(uint32 size);

				/*********************************************************************************
				 * Get buffer raw ptr
				 ********************************************************************************/
				PUMP_INLINE c_block_ptr raw() const
				{ return buffer_; }

				/*********************************************************************************
				 * Get buffer raw size
				 ********************************************************************************/
				PUMP_INLINE uint32 raw_size() const
				{  return buffer_size_; }

				/*********************************************************************************
				 * Get data ptr
				 ********************************************************************************/
				PUMP_INLINE c_block_ptr data() const
				{ return data_size_ == 0 ? nullptr : (buffer_ + data_pos_); }

				/*********************************************************************************
				 * Get data size
				 ********************************************************************************/
				PUMP_INLINE uint32 data_size() const
				{ return data_size_; }

			private:
				block_ptr buffer_;
				uint32 buffer_size_;

				uint32 data_pos_;
				uint32 data_size_;
			};
			DEFINE_ALL_POINTER_TYPE(buffer);

		}
	}
}

#endif