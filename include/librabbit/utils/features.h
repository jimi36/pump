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

#ifndef librabbit_utils_features_h
#define librabbit_utils_features_h

#include "librabbit/deps.h"
#include "function/function.h"

namespace librabbit {
	namespace utils {

		class LIB_EXPORT noncopyable
		{
		protected:
			noncopyable() {}
			virtual ~noncopyable() {}

		private:
			noncopyable(noncopyable&);
			noncopyable& operator=(noncopyable&);
		};

		class LIB_EXPORT scoped_defer: public noncopyable
		{
		protected:
			typedef function::function<void()> defer_callback;

		public:
			scoped_defer(const defer_callback &&cb)
			{
				cb_ = cb;
			}

			virtual ~scoped_defer()
			{
				if (cb_) cb_();
			}

			void clear()
			{
				cb_.reset();
			}

		private:
			defer_callback cb_;
		};

	}
}

#endif