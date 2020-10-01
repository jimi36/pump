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
#include "pump/debug.h"
#include "pump/net/iocp.h"

// Import "memset" on linux
#include <string.h>

#if defined(OS_LINUX)
#include <signal.h>
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {

#if defined(OS_LINUX)
typedef void (*sighandler_t)(int32);
static bool setup_signal(int32 sig, int32 flags, sighandler_t hdl) {
    // Blocking the same signal when signal hander is running
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    sigaddset(&act.sa_mask, sig);
    act.sa_flags = flags;
    act.sa_handler = hdl;

    if (sigaction(sig, &act, NULL) != 0) {
        PUMP_WARN_LOG("pump::setup_signal: sigaction failed sig=%d", sig);
        return false;
    }

    return true;
}
#endif

bool init() {
#if defined(OS_WINDOWS)
    WSADATA wsaData;
    WORD wVersionRequested;
    wVersionRequested = MAKEWORD(2, 2);
    ::WSAStartup(wVersionRequested, &wsaData);
#elif defined(OS_LINUX)
    setup_signal(SIGPIPE, 0, SIG_IGN);
#endif

#if defined(PUMP_HAVE_GNUTLS)
    if (gnutls_global_init() != 0) {
        PUMP_WARN_LOG("pump::init: gnutls_global_init failed");
        return false;
    }
    gnutls_global_set_log_level(0);
#endif

    return true;
}

void uninit() {
#if defined(OS_WINDOWS)
    ::WSACleanup();
#elif defined(OS_LINUX)
    setup_signal(SIGPIPE, 0, SIG_DFL);
#endif

#if defined(PUMP_HAVE_IOCP)
    CloseHandle(net::get_iocp_handler());
#endif

#if defined(PUMP_HAVE_GNUTLS)
    gnutls_global_deinit();
#endif
}

}  // namespace pump