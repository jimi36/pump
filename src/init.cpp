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

#include "pump/init.h"

#ifdef USE_GNUTLS
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {

#ifndef WIN32 
	typedef void(*sighandler_t)(int32);
	static bool setup_signal(int32 sig, int32 flags, sighandler_t hdl)
	{
		// Blocking the same signal when signal hander is running
		struct sigaction act;

		memset(&act, 0, sizeof(act));
		sigaddset(&act.sa_mask, sig);
		act.sa_flags = flags;
		act.sa_handler = hdl;

		if (sigaction(sig, &act, NULL) != 0)
		{
			return false;
		}

		return true;
	}
#endif

	bool init()
	{
#ifdef WIN32
		WSADATA wsaData;
		WORD wVersionRequested;
		wVersionRequested = MAKEWORD(2, 2);
		::WSAStartup(wVersionRequested, &wsaData);
#else
		setup_signal(SIGPIPE, 0, SIG_IGN);
#endif

#ifdef USE_GNUTLS
		if (gnutls_global_init() != 0)
			return false;
		gnutls_global_set_log_level(0);
#endif

		return true;
	}

	void uninit()
	{
#ifdef WIN32
		::WSACleanup();
#else
		setup_signal(SIGPIPE, 0, SIG_DFL);
#endif

#ifdef USE_GNUTLS
		gnutls_global_deinit();
#endif
	}

}