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

#ifndef pump_codec_sha1_h
#define pump_codec_sha1_h

#include "pump/types.h"
#include "pump/platform.h"

namespace pump {
namespace codec {

struct sha1_context {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
};

/*********************************************************************************
 * Init sha1 context
 ********************************************************************************/
pump_lib void sha1_init(sha1_context *ctx);

/*********************************************************************************
 * Update sha1 context
 ********************************************************************************/
pump_lib void sha1_update(
    sha1_context *ctx,
    const char *data,
    int32_t size);

/*********************************************************************************
 * Final sha1 context
 ********************************************************************************/
pump_lib void sha1_final(
    sha1_context *ctx,
    uint8_t digest[20]);

/*********************************************************************************
 * Sha1
 ********************************************************************************/
pump_lib void sha1(
    const char *data,
    int32_t size,
    uint8_t digest[20]);

}  // namespace codec
}  // namespace pump

#endif
