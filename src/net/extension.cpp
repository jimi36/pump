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

#include "pump/net/extension.h"

namespace pump {
	namespace net {

#ifdef WIN32
		void_ptr get_extension_function(int32 fd, const GUID *which_fn)
		{
			DWORD bytes = 0;
			void_ptr ptr = nullptr;
			WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
				(GUID*)which_fn, sizeof(*which_fn), &ptr, sizeof(ptr), &bytes, nullptr, nullptr);

			return ptr;
		}
#endif

		struct net_extension
		{
#ifdef WIN32
			net_extension()
			{
				accept_ex = nullptr;
				connect_ex = nullptr;
				get_accepted_addrs = nullptr;
			}

			LPFN_ACCEPTEX accept_ex;
			LPFN_CONNECTEX connect_ex;
			LPFN_GETACCEPTEXSOCKADDRS get_accepted_addrs;
#endif
		};

		net_extension_ptr new_net_extension(int32 fd)
		{
#ifdef WIN32
			GUID guid_accept_ex = WSAID_ACCEPTEX;
			LPFN_ACCEPTEX accept_ex = (LPFN_ACCEPTEX)get_extension_function(fd, &guid_accept_ex);
			GUID guid_get_acceptex_sockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
			LPFN_GETACCEPTEXSOCKADDRS get_accepted_addrs = (LPFN_GETACCEPTEXSOCKADDRS)get_extension_function(fd, &guid_get_acceptex_sockaddrs);
			GUID guid_connect_ex = WSAID_CONNECTEX;
			LPFN_CONNECTEX connect_ex = (LPFN_CONNECTEX)get_extension_function(fd, &guid_connect_ex);
			if (accept_ex == nullptr || get_accepted_addrs == nullptr || connect_ex == nullptr)
				return nullptr;

			auto ext = new net_extension;
			ext->accept_ex = accept_ex;
			ext->connect_ex = connect_ex;
			ext->get_accepted_addrs = get_accepted_addrs;

			return ext;
#else
			return nullptr;
#endif
		}

		void delete_net_extension(net_extension_ptr ext)
		{
#ifdef WIN32
			if (ext)
				delete ext;
#endif
		}

		void_ptr get_accpet_ex_func(net_extension_ptr ext)
		{
#ifdef WIN32
			if (ext)
				return ext->accept_ex;
#endif
			return nullptr;
		}

		void_ptr get_accepted_addrs_func(net_extension_ptr ext)
		{
#ifdef WIN32
			if (ext)
				return ext->get_accepted_addrs;
#endif
			return nullptr;
		}

		void_ptr get_connect_ex_func(net_extension_ptr ext)
		{
#ifdef WIN32
			if (ext)
				return ext->connect_ex;
#endif
			return nullptr;
		}

	}
}