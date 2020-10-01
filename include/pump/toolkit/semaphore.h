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

#ifndef pump_toolkit_semaphone_h
#define pump_toolkit_semaphone_h

#include <atomic>
#include <cstddef>      // For std::size_t
#include <type_traits>  // For std::make_signed<T>

#include "pump/debug.h"
#include "pump/types.h"
#include "pump/config.h"
#include "pump/toolkit/features.h"

#if defined(OS_WINDOWS)
// Avoid including windows.h in a header; we only need a handful of
// items, so we'll redeclare them here (this is relatively safe since
// the API generally has to remain stable between Windows versions).
// I know this is an ugly hack but it still beats polluting the global
// namespace with thousands of generic names or adding a .cpp for nothing.
extern "C" {
struct _SECURITY_ATTRIBUTES;
__declspec(dllimport) void *__stdcall CreateSemaphoreW(
    _SECURITY_ATTRIBUTES *lpSemaphoreAttributes,
    long lInitialCount,
    long lMaximumCount,
    const wchar_t *lpName);
__declspec(dllimport) int __stdcall CloseHandle(void *hObject);
__declspec(dllimport) unsigned long __stdcall WaitForSingleObject(
    void *hHandle, unsigned long dwMilliseconds);
__declspec(dllimport) int __stdcall ReleaseSemaphore(void *hSemaphore,
                                                     long lReleaseCount,
                                                     long *lpPreviousCount);
}
#elif defined(OS_LINUX)
#include <semaphore.h>
#endif

namespace pump {
namespace toolkit {

    class LIB_PUMP semaphore : public noncopyable {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        semaphore(int32 ini_count = 0) {
#if defined(OS_WINDOWS)
            const long maxLong = 0x7fffffff;
            sema_ = CreateSemaphoreW(nullptr, ini_count, maxLong, nullptr);
            PUMP_ASSERT(sema_);
#elif defined(OS_LINUX)
            int32 rc = sem_init(&sema_, 0, ini_count);
            PUMP_ASSERT(rc == 0);
#endif
        }

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~semaphore() {
#if defined(OS_WINDOWS)
            CloseHandle(sema_);
#elif defined(OS_LINUX)
            sem_destroy(&sema_);
#endif
        }

        /*********************************************************************************
         * Wait
         * Wait for the signal forever.
         ********************************************************************************/
        bool wait() {
#if defined(OS_WINDOWS)
            const unsigned long infinite = 0xffffffff;
            return WaitForSingleObject(sema_, infinite) == 0;
#elif defined(OS_LINUX)
            int32 rc;
            do {
                rc = sem_wait(&sema_);
            } while (rc == -1 && errno == EINTR);
            return rc == 0;
#endif
        }

        /*********************************************************************************
         * Try wait
         * Wait for the signal, but return immediately.
         ********************************************************************************/
        bool try_wait() {
#if defined(OS_WINDOWS)
            return WaitForSingleObject(sema_, 0) == 0;
#elif defined(OS_LINUX)
            int32 rc;
            do {
                rc = sem_trywait(&sema_);
            } while (rc == -1 && errno == EINTR);
            return rc == 0;
#endif
        }

        /*********************************************************************************
         * Wait with timeout
         * Wait for the signal until timeout.
         ********************************************************************************/
        bool wait_with_timeout(uint64 usecs) {
#if defined(OS_WINDOWS)
            return WaitForSingleObject(sema_, (unsigned long)(usecs / 1000)) == 0;
#elif defined(OS_LINUX)
            struct timespec ts;
            const int32 usecs_in_1_sec = 1000000;
            const int32 nsecs_in_1_sec = 1000000000;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (time_t)(usecs / usecs_in_1_sec);
            ts.tv_nsec += (long)(usecs % usecs_in_1_sec) * 1000;
            // sem_timedwait bombs if you have more than 1e9 in tv_nsec
            // so we have to clean things up before passing it in
            if (ts.tv_nsec >= nsecs_in_1_sec) {
                ts.tv_nsec -= nsecs_in_1_sec;
                ++ts.tv_sec;
            }

            int32 rc;
            do {
                rc = sem_timedwait(&sema_, &ts);
            } while (rc == -1 && errno == EINTR);
            return rc == 0;
#endif
        }

        /*********************************************************************************
         * Signal
         ********************************************************************************/
        void signal() {
#if defined(OS_WINDOWS)
            while (!ReleaseSemaphore(sema_, 1, nullptr))
                ;
#elif defined(OS_LINUX)
            while (count-- > 0) {
                while (sem_post(&sema_) == -1)
                    ;
            }
#endif
        }

        /*********************************************************************************
         * Signal
         ********************************************************************************/
        void signal(int32 count = 1) {
#if defined(OS_WINDOWS)
            while (!ReleaseSemaphore(sema_, count, nullptr))
                ;
#elif defined(OS_LINUX)
            while (sem_post(&sema_) == -1)
                ;
#endif
        }

      private:
#if defined(OS_WINDOWS)
        void *sema_;
#elif defined(OS_LINUX)
        sem_t sema_;
#endif
    };

    class LIB_PUMP light_semaphore : public noncopyable {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        light_semaphore(int64 init_count = 0) : count_(init_count) {
            assert(init_count >= 0);
        }

        /*********************************************************************************
         * Try wait one signal and return immediately
         ********************************************************************************/
        bool try_wait() {
            int64 old_count = count_.load(std::memory_order_relaxed);
            while (old_count > 0) {
                if (count_.compare_exchange_weak(old_count,
                                                 old_count - 1,
                                                 std::memory_order_acquire,
                                                 std::memory_order_relaxed))
                    return true;
            }
            return false;
        }

        /*********************************************************************************
         * Wait one signal without timeout
         ********************************************************************************/
        bool wait() {
            return try_wait() || __wait_with_spinning();
        }

        /*********************************************************************************
         * Wait one signal with timeout
         ********************************************************************************/
        bool wait(int64 timeout_usecs) {
            return try_wait() || __wait_with_spinning(timeout_usecs);
        }

        /*********************************************************************************
         * Signal
         ********************************************************************************/
        void signal(int64 count = 1) {
            PUMP_ASSERT(count >= 0);
            int64 old_count = count_.fetch_add(count, std::memory_order_release);
            int64 to_release = -old_count < count ? -old_count : count;
            if (to_release > 0)
                semaphone_.signal((int32)to_release);
        }

        /*********************************************************************************
         * Get signal count
         ********************************************************************************/
        int64 count() const {
            int64 count = count_.load(std::memory_order_relaxed);
            return count > 0 ? count : 0;
        }

      private:
        /*********************************************************************************
         * Wait with spinning and timeout
         ********************************************************************************/
        bool __wait_with_spinning(int64 timeout_usecs = -1) {
            int64 old_count;
            // Is there a better way to set the initial spin count?
            // If we lower it to 1000, testBenaphore becomes 15x slower on my Core
            // i7-5930K Windows PC, as threads start hitting the kernel semaphore.
            int32 spin = 10000;
            while (--spin >= 0) {
                old_count = count_.load(std::memory_order_relaxed);
                if ((old_count > 0) &&
                    count_.compare_exchange_strong(old_count,
                                                   old_count - 1,
                                                   std::memory_order_acquire,
                                                   std::memory_order_relaxed))
                    return true;
                // Prevent the compiler from collapsing the loop.
                std::atomic_signal_fence(std::memory_order_acquire);
            }
            old_count = count_.fetch_sub(1, std::memory_order_acquire);
            if (old_count > 0)
                return true;
            if (timeout_usecs < 0)
                return semaphone_.wait();
            if (semaphone_.wait_with_timeout((uint64)timeout_usecs))
                return true;
            // At this point, we've timed out waiting for the semaphore, but the
            // count is still decremented indicating we may still be waiting on
            // it. So we have to re-adjust the count, but only if the semaphore
            // wasn't signaled enough times for us too since then. If it was, we
            // need to release the semaphore too.
            while (true) {
                old_count = count_.load(std::memory_order_acquire);
                if (old_count >= 0 && semaphone_.try_wait())
                    return true;
                if (old_count < 0 &&
                    count_.compare_exchange_strong(old_count,
                                                   old_count + 1,
                                                   std::memory_order_relaxed,
                                                   std::memory_order_relaxed))
                    return false;
            }
        }

      private:
        semaphore semaphone_;
        std::atomic_int64_t count_;
    };

}  // namespace toolkit
}  // namespace pump

#endif
