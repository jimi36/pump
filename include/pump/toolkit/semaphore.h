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

#include "pump/debug.h"
#include "pump/types.h"
#include "pump/toolkit/features.h"

#if defined(OS_LINUX)
#include <semaphore.h>
#endif

namespace pump {
namespace toolkit {

class pump_lib semaphore : public noncopyable {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    semaphore(int32_t ini_count = 0) {
#if defined(OS_WINDOWS)
        const long maxLong = 0x7fffffff;
        sema_ = CreateSemaphoreW(nullptr, ini_count, maxLong, nullptr);
        pump_assert(sema_);
#elif defined(OS_LINUX)
        if (sem_init(&sema_, 0, ini_count) != 0) {
            pump_assert(false);
        }
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
        int32_t rc;
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
        int32_t rc;
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
    bool wait_with_timeout(uint64_t usecs) {
#if defined(OS_WINDOWS)
        return WaitForSingleObject(sema_, (unsigned long)(usecs / 1000)) == 0;
#elif defined(OS_LINUX)
        struct timespec ts;
        const static int32_t usecs_in_1_sec = 1000000;
        const static int32_t nsecs_in_1_sec = 1000000000;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (time_t)(usecs / usecs_in_1_sec);
        ts.tv_nsec += (long)(usecs % usecs_in_1_sec) * 1000;
        // sem_timedwait bombs if you have more than 1e9 in tv_nsec
        // so we have to clean things up before passing it in
        if (ts.tv_nsec >= nsecs_in_1_sec) {
            ts.tv_nsec -= nsecs_in_1_sec;
            ++ts.tv_sec;
        }

        int32_t rc;
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
        while (!ReleaseSemaphore(sema_, 1, nullptr)) {
        }
#elif defined(OS_LINUX)
        while (sem_post(&sema_) == -1) {
        }
#endif
    }

    /*********************************************************************************
     * Signal
     ********************************************************************************/
    void signal(int32_t count = 1) {
#if defined(OS_WINDOWS)
        while (!ReleaseSemaphore(sema_, count, nullptr)) {
        }
#elif defined(OS_LINUX)
        while (count-- > 0) {
            while (sem_post(&sema_) == -1) {
            }
        }
#endif
    }

  private:
#if defined(OS_WINDOWS)
    void *sema_;
#elif defined(OS_LINUX)
    sem_t sema_;
#endif
};

class pump_lib light_semaphore : public noncopyable {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    light_semaphore(int32_t max_spin = 10000, int64_t init_count = 0)
      : max_spin_(max_spin), count_(init_count) {
        assert(init_count >= 0);
    }

    /*********************************************************************************
     * Try wait one signal and return immediately
     ********************************************************************************/
    bool try_wait() {
        int64_t old_count = count_.load(std::memory_order_relaxed);
        while (old_count > 0) {
            if (count_.compare_exchange_weak(
                    old_count,
                    old_count - 1,
                    std::memory_order_acquire,
                    std::memory_order_relaxed)) {
                return true;
            }
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
    bool wait(int64_t timeout_usecs) {
        return try_wait() || __wait_with_spinning(timeout_usecs);
    }

    /*********************************************************************************
     * Signal
     ********************************************************************************/
    void signal(int64_t count = 1) {
        pump_assert(count >= 0);
        int64_t old_count = count_.fetch_add(count, std::memory_order_release);
        int64_t to_release = -old_count < count ? -old_count : count;
        if (to_release > 0) {
            semaphone_.signal((int32_t)to_release);
        }
    }

    /*********************************************************************************
     * Get signal count
     ********************************************************************************/
    int64_t count() const {
        int64_t count = count_.load(std::memory_order_relaxed);
        return count > 0 ? count : 0;
    }

  private:
    /*********************************************************************************
     * Wait with spinning and timeout
     ********************************************************************************/
    bool __wait_with_spinning(int64_t timeout_usecs = -1) {
        int64_t old_count;
        // Is there a better way to set the initial spin count?
        // If we lower it to 1000, testBenaphore becomes 15x slower on my Core
        // i7-5930K Windows PC, as threads start hitting the kernel semaphore.
        int32_t spin = max_spin_;
        while (--spin >= 0) {
            old_count = count_.load(std::memory_order_relaxed);
            if ((old_count > 0) &&
                count_.compare_exchange_strong(
                    old_count,
                    old_count - 1,
                    std::memory_order_acquire,
                    std::memory_order_relaxed)) {
                return true;
            }
            // Prevent the compiler from collapsing the loop.
            std::atomic_signal_fence(std::memory_order_acquire);
        }
        old_count = count_.fetch_sub(1, std::memory_order_acquire);
        if (old_count > 0) {
            return true;
        }
        if (timeout_usecs < 0) {
            return semaphone_.wait();
        }
        if (semaphone_.wait_with_timeout((uint64_t)timeout_usecs)) {
            return true;
        }
        // At this point, we've timed out waiting for the semaphore, but the
        // count is still decremented indicating we may still be waiting on
        // it. So we have to re-adjust the count, but only if the semaphore
        // wasn't signaled enough times for us too since then. If it was, we
        // need to release the semaphore too.
        while (true) {
            old_count = count_.load(std::memory_order_acquire);
            if (old_count >= 0 && semaphone_.try_wait()) {
                return true;
            }
            if (old_count < 0 &&
                count_.compare_exchange_strong(
                    old_count,
                    old_count + 1,
                    std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
                return false;
            }
        }
    }

  private:
    semaphore semaphone_;

    int32_t max_spin_;
    std::atomic_int64_t count_;
};

}  // namespace toolkit
}  // namespace pump

#endif
