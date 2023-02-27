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

#include <pump/types.h>
#include <pump/memory.h>

namespace pump {
namespace toolkit {

/*********************************************************************************
 * Noncopyable base class
 ********************************************************************************/
class pump_lib noncopyable {
  protected:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    noncopyable() = default;

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~noncopyable() = default;

  private:
    /*********************************************************************************
     * Disable copy constructor
     ********************************************************************************/
    noncopyable(const noncopyable &) = delete;

    /*********************************************************************************
     * Disable copy assign operator
     ********************************************************************************/
    const noncopyable &operator=(const noncopyable &) = delete;
};

/*********************************************************************************
 * Defer class
 ********************************************************************************/
class pump_lib defer : public noncopyable {
  public:
    /*********************************************************************************
     * Constructor
     ********************************************************************************/
    defer(const pump_function<void()> &cb) noexcept {
        cb_ = cb;
    }
    defer(pump_function<void()> &&cb) noexcept {
        cb_ = std::move(cb);
    }

    /*********************************************************************************
     * Deconstructor
     ********************************************************************************/
    ~defer() {
        if (cb_) {
            cb_();
        }
    }

    /*********************************************************************************
     * Clear
     ********************************************************************************/
    pump_inline void clear() noexcept {
        cb_ = pump_function<void()>();
    }

  private:
    // Callback
    pump_function<void()> cb_;
};

}  // namespace toolkit
}  // namespace pump

#endif