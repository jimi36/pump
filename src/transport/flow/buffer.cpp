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

			bool buffer::append(c_block_ptr b, int32 size)
			{
				if (!b || size == 0)
					return false;

				if (rpos_ != 0 && rpos_ == (int32)raw_.size())
					reset();

				raw_.append(b, size);

				return true;
			}

			bool buffer::shift(int32 size)
			{
				if ((int32)raw_.size() < rpos_ + size)
					return false;
				rpos_ += size;
				return true;
			}

		}
	}
}
