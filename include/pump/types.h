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

#ifndef pump_types_h
#define pump_types_h

#define DEFINE_RAW_POINTER_TYPE(class_name) \
	typedef class_name* class_name##_ptr; \
	typedef const class_name* c_##class_name##_ptr;

#define DEFINE_SMART_POINTER_TYPE(class_name) \
	typedef std::weak_ptr<class_name> class_name##_wptr; \
	typedef const std::weak_ptr<class_name> c_##class_name##_wptr; \
	typedef std::shared_ptr<class_name> class_name##_sptr; \
	typedef const std::shared_ptr<class_name> c_##class_name##_sptr;

#define DEFINE_ALL_POINTER_TYPE(class_name) \
	DEFINE_RAW_POINTER_TYPE(class_name) \
	DEFINE_SMART_POINTER_TYPE(class_name)

namespace pump {

	typedef char int8;
	DEFINE_RAW_POINTER_TYPE(int8);

	typedef unsigned char uint8;
	DEFINE_RAW_POINTER_TYPE(uint8);

	typedef short int16;
	DEFINE_RAW_POINTER_TYPE(int16);

	typedef unsigned short uint16;
	DEFINE_RAW_POINTER_TYPE(uint16);

	typedef int int32;
	DEFINE_RAW_POINTER_TYPE(int32);

	typedef unsigned int uint32;
	DEFINE_RAW_POINTER_TYPE(uint32);

#ifdef _MSC_VER
	typedef signed __int64 int64;
	DEFINE_RAW_POINTER_TYPE(int64);

	typedef unsigned __int64 uint64;
	DEFINE_RAW_POINTER_TYPE(uint64);
#else
	typedef long long int64;
	DEFINE_RAW_POINTER_TYPE(int64);

	typedef unsigned long long uint64;
	DEFINE_RAW_POINTER_TYPE(uint64);
#endif

	typedef float float32;
	DEFINE_RAW_POINTER_TYPE(float32);

	typedef double float64;
	DEFINE_RAW_POINTER_TYPE(float64);

	typedef int8 block;
	DEFINE_RAW_POINTER_TYPE(block);

	DEFINE_ALL_POINTER_TYPE(void);

	template <typename ClassSrc, typename ClassDes>
	std::shared_ptr<ClassDes> static_pointer_cast(const std::shared_ptr<ClassSrc> &sptr)
	{
		return std::move(std::static_pointer_cast<ClassDes>(sptr));
	}
}

#endif