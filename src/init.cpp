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

#if defined(PUMP_HAVE_TLS)
extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}
#endif

namespace pump {

#if defined(OS_LINUX)
typedef void (*sighandler_t)(int32_t);
static bool setup_signal(int32_t sig, sighandler_t handler) {
    if (signal(sig, NULL) != 0) {
        pump_debug_log("setup signal %d failed", sig);
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
            if (s_inited_count.compare_exchange_strong(
                    inited_count,
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
        pump_debug_log("init win socket library failed");
        return false;
    }
#if defined(PUMP_HAVE_IOCP)
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        return false;
    }
    NtCreateFile = (FnNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
    if (NtCreateFile == nullptr) {
        return false;
    }
    NtDeviceIoControlFile = (FnNtDeviceIoControlFile)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    if (NtDeviceIoControlFile == nullptr) {
        return false;
    }
    NtCancelIoFileEx = (FnNtCancelIoFileEx)GetProcAddress(ntdll, "NtCancelIoFileEx");
    if (NtCancelIoFileEx == nullptr) {
        return false;
    }
#endif
#endif

#if defined(OS_LINUX)
    setup_signal(SIGPIPE, SIG_IGN);
#endif

#if defined(PUMP_HAVE_TLS)
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
            if (s_inited_count.compare_exchange_strong(
                    inited_count,
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

    s_inited_count.store(0);
}

}  // namespace pump