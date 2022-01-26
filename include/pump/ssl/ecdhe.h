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

    // TLS curve ecdhe types.
    // https://tools.ietf.org/html/rfc8446#section-4.2.7
    typedef uint16_t curve_group_type;
    const curve_group_type TLS_CURVE_UNKNOWN = 0;
    const curve_group_type TLS_CURVE_P256    = 0x0017; // secp256r1
    const curve_group_type TLS_CURVE_P384    = 0x0018; // secp384r1
    const curve_group_type TLS_CURVE_P521    = 0x0019; // secp521r1
    const curve_group_type TLS_CURVE_X25519  = 0x001D;
    const curve_group_type TLS_CURVE_X448    = 0x001E;

    struct ecdhe_context {
        curve_group_type group;
        std::string prikey;
        std::string pubkey;
    };

    /*********************************************************************************
     * New ecdhe context.
     ********************************************************************************/
    ecdhe_context* new_ecdhe_context(curve_group_type curve);

    /*********************************************************************************
     * Delete ecdhe context.
     ********************************************************************************/
    void delete_ecdhe_context(ecdhe_context *ctx);

    /*********************************************************************************
     * Generate ecdhe shared key.
     ********************************************************************************/
    bool gen_ecdhe_shared_key(
        ecdhe_context *ctx, 
        const std::string &pubkey,
        std::string &shared_key);

}
}

#endif