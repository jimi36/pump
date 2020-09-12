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

#ifndef pump_toolkit_features_h
#define pump_toolkit_features_h

#include "pump/fncb.h"
#include "pump/platform.h"

namespace pump {
namespace toolkit {

    /*********************************************************************************
     * Noncopyable base class
     ********************************************************************************/
    class LIB_PUMP noncopyable {
      protected:
        noncopyable() = default;
        ~noncopyable() = default;

        noncopyable(noncopyable &) = delete;
        noncopyable &operator=(noncopyable &) = delete;
    };

    /*********************************************************************************
     * Defer class
     ********************************************************************************/
    class LIB_PUMP defer : public noncopyable {
      public:
        defer(const pump_function<void()> &&cb) {
            cb_ = cb;
        }

        ~defer() {
            if (cb_)
                cb_();
        }

        PUMP_INLINE void clear() {
            cb_ = pump_function<void()>();
        }

      private:
        pump_function<void()> cb_;
    };

}  // namespace toolkit
}  // namespace pump

#endif