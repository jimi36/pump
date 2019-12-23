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

#ifndef pump_net_extension_h
#define pump_net_extension_h

#include "pump/deps.h"

namespace pump {
	namespace net {

		struct net_extension;
		DEFINE_ALL_POINTER_TYPE(net_extension);

		/*********************************************************************************
		 * New net extension
		 ********************************************************************************/
		net_extension_ptr new_net_extension(int32 fd);

		/*********************************************************************************
		 * Delete net extension
		 ********************************************************************************/
		void delete_net_extension(net_extension_ptr ext);

		/*********************************************************************************
		 * Get LPFN_ACCEPTEX func from extension
		 ********************************************************************************/
		void_ptr get_accpet_ex_func(net_extension_ptr ext);

		/*********************************************************************************
		 * Get LPFN_GETACCEPTEXSOCKADDRS func from extension
		 ********************************************************************************/
		void_ptr get_accepted_addrs_func(net_extension_ptr ext);

		/*********************************************************************************
		 * Get LPFN_CONNECTEX func from extension
		 ********************************************************************************/
		void_ptr get_connect_ex_func(net_extension_ptr ext);

	}
}

#endif