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

#include "pump/transport/flow/buffer.h"

namespace pump {
	namespace transport {
		namespace flow {

			buffer::buffer() noexcept :
				buffer_(nullptr),
				buffer_size_(0),
				data_pos_(0),
				data_size_(0)
			{
			}

			buffer::~buffer()
			{
				if (buffer_ != nullptr)
					pump_free(buffer_);
			}

			bool buffer::append(c_block_ptr b, uint32 size)
			{
				if (!b || size == 0)
					return false;

				if (data_pos_ != 0 && data_pos_ == buffer_size_)
					reset();

				if (buffer_ == nullptr)
				{
					buffer_ = (block_ptr)pump_malloc(size);
					if (buffer_ == nullptr)
						return false;
					buffer_size_ = size;

					memcpy(buffer_, b, size);
			
					data_pos_ = 0;
					data_size_ = size;
				}
				else 
				{
					uint32 left = buffer_size_ - data_pos_ - data_size_;
					if (size < left)
					{
						memcpy(buffer_ + data_pos_ + data_size_, b, size);
						data_size_ += size;
					}
					else if (size + data_size_ < buffer_size_)
					{
						memcpy(buffer_, buffer_ + data_pos_, data_size_);
						memcpy(buffer_+ data_size_, b, size);

						data_pos_ = 0;
						data_size_ += size;
					}
					else
					{
						uint32 new_size_ = buffer_size_ + size * 2;
						buffer_ = (block_ptr)pump_realloc(buffer_, new_size_);
						buffer_size_ = new_size_;

						memcpy(buffer_ + data_pos_ + data_size_, b, size);

						data_size_ += size;
					}
				}

				return true;
			}

			bool buffer::shift(uint32 size)
			{
				if (size > data_size_)
					return false;

				data_pos_ += size;
				data_size_ -= size;

				return true;
			}

		}
	}
}
