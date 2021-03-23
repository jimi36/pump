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

#ifndef pump_ssl_ecdhe_h
#define pump_ssl_ecdhe_h

#include <string>
#include <vector>

#include "pump/types.h"

namespace pump {
namespace ssl {

    struct ecdhe_parameter;
    DEFINE_RAW_POINTER_TYPE(ecdhe_parameter);

    /*********************************************************************************
     * Crypto key pair.
     ********************************************************************************/
    struct key_pair {
        std::string prikey;
        std::string pubkey;
    };

    /*********************************************************************************
     * X25519 key pair init.
     ********************************************************************************/
    bool X25519_init(key_pair *kp);

    /*********************************************************************************
     * X25519 device data.
     ********************************************************************************/
    bool X25519_device(key_pair *kp, const std::string &data, std::string &out);

}
}

#endif