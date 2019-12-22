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

#include "librabbit/transport/flow/buffer.h"

namespace librabbit {
	namespace transport {
		namespace flow {

			buffer::buffer():
				rpos_(0)
			{
			}

			buffer::~buffer()
			{
			}

			bool buffer::init(c_block_ptr b, uint32 size)
			{
				if (!b || size == 0)
					return false;

				if (!raw_.empty())
					return false;

				raw_.assign(b, size);

				return true;
			}

			bool buffer::append(c_block_ptr b, uint32 size)
			{
				if (!b || size == 0)
					return false;

				if (rpos_ == (uint32)raw_.size())
					reset();

				raw_.append(b, size);

				return true;
			}

			void buffer::reset()
			{
				raw_.clear();
				rpos_ = 0;
			}

			bool buffer::shift(uint32 size)
			{
				if (size == 0)
					return false;

				if (raw_.size() < rpos_ + size)
					return false;

				rpos_ += size;

				return true;
			}

			block_ptr buffer::ptr()
			{
				if (raw_.empty())
					return nullptr;
				return (int8*)raw_.data();
			}

			c_block_ptr buffer::data()
			{
				if (raw_.empty())
					return nullptr;
				return raw_.data() + rpos_;
			}

			uint32 buffer::data_size()
			{
				uint32 size = (uint32)raw_.size();
				return size - rpos_;
			}

		}
	}
}
