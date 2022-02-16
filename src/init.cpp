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
#include "pump/platform.h"
#include "pump/net/iocp.h"

#include <string.h>

#if defined(OS_LINUX)
#include <signal.h>
#endif

#if defined(PUMP_HAVE_OPENSSL)
extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {

#if defined(OS_LINUX)
typedef void (*sighandler_t)(int32_t);
static bool setup_signal(int32_t sig, sighandler_t handler) {
    if (signal(sig, NULL) != 0) {
        PUMP_WARN_LOG("setup_signal: signal failed sig=%d", sig);
        return false;
    }
    return true;
}
#endif

static std::atomic_int s_inited_count(0);

bool init() {
    while (true) {
        int32_t inited_count = s_inited_count.load();
        if (inited_count == -1) {
            return false;
        } else if (inited_count > 0) {
            if (s_inited_count.compare_exchange_strong(inited_count,
                                                       inited_count + 1)) {
                return true;
            }
        } else {
            if (s_inited_count.compare_exchange_strong(inited_count, -1)) {
                break;
            }
        }
    }

#if defined(PUMP_HAVE_WINSOCK)
    WSADATA wsaData;
    WORD wVersionRequested;
    wVersionRequested = MAKEWORD(2, 2);
    if (::WSAStartup(wVersionRequested, &wsaData) == SOCKET_ERROR) {
        PUMP_WARN_LOG("init: WSAStartup failed");
        return false;
    }
#if defined(PUMP_HAVE_IOCP)
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        return false;
    }
    if ((NtCreateFile =
             (FnNtCreateFile)GetProcAddress(ntdll, "NtCreateFile")) ==
        nullptr) {
        return false;
    }
    if ((NtDeviceIoControlFile = (FnNtDeviceIoControlFile)
             GetProcAddress(ntdll, "NtDeviceIoControlFile")) == nullptr) {
        return false;
    }
    if ((NtCancelIoFileEx =
             (FnNtCancelIoFileEx)GetProcAddress(ntdll, "NtCancelIoFileEx")) ==
        nullptr) {
        return false;
    }
#endif
#endif

#if defined(OS_LINUX)
    setup_signal(SIGPIPE, SIG_IGN);
#endif

#if defined(PUMP_HAVE_GNUTLS)
    if (gnutls_global_init() != 0) {
        PUMP_WARN_LOG("init: gnutls_global_init failed");
        return false;
    }
    gnutls_global_set_log_level(0);
#elif defined(PUMP_HAVE_OPENSSL)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif

    s_inited_count.store(1);

    return true;
}

void uninit() {
    while (true) {
        int32_t inited_count = s_inited_count.load();
        if (inited_count <= 0) {
            return;
        } else if (inited_count > 1) {
            if (s_inited_count.compare_exchange_strong(inited_count,
                                                       inited_count - 1)) {
                return;
            }
        } else {
            if (s_inited_count.compare_exchange_strong(inited_count, -1)) {
                break;
            }
        }
    }

#if defined(PUMP_HAVE_WINSOCK)
    ::WSACleanup();
#endif

#if defined(OS_LINUX)
    setup_signal(SIGPIPE, SIG_DFL);
#endif

#if defined(PUMP_HAVE_GNUTLS)
    gnutls_global_deinit();
#endif

    s_inited_count.store(0);
}

}  // namespace pump