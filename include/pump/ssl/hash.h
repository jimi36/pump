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

#ifndef pump_ssl_hash_h
#define pump_ssl_hash_h

#include <string>

#include "pump/types.h"

namespace pump {
namespace ssl {

    typedef int64_t hash_algorithm;
    const hash_algorithm HASH_UNKNOWN = 0;
    const hash_algorithm HASH_SHA1    = 1;
    const hash_algorithm HASH_SHA224  = 2;
    const hash_algorithm HASH_SHA256  = 3;
    const hash_algorithm HASH_SHA384  = 4;
    const hash_algorithm HASH_SHA512  = 5;

    struct hash_context;
    DEFINE_RAW_POINTER_TYPE(hash_context);

    /*********************************************************************************
     * Hash digest length.
      ********************************************************************************/
    int32_t hash_digest_length(hash_algorithm algo);

    /*********************************************************************************
     * Create hash context
     ********************************************************************************/
    hash_context_ptr create_hash_context(hash_algorithm algo);

    /*********************************************************************************
     * Free hash context
     ********************************************************************************/
    void free_hash_context(hash_context_ptr ctx);

    /*********************************************************************************
     * Reset hash context
     ********************************************************************************/
    void reset_hash_context(hash_context_ptr ctx);

    /*********************************************************************************
     * Update ash 
     ********************************************************************************/
    bool update_hash(
        hash_context_ptr ctx, 
        const std::string &data);
    bool update_hash(
        hash_context_ptr ctx, 
        const uint8_t *data, int32_t data_len);

    /*********************************************************************************
     * Sum hash
     ********************************************************************************/
    bool sum_hash(
        hash_context_ptr ctx, 
        uint8_t *out, 
        int32_t out_len);
    std::string sum_hash(hash_context_ptr ctx);

    /*********************************************************************************
     * Sum hmac
     ********************************************************************************/
    std::string sum_hmac(
        hash_algorithm algo,
        const std::string &key,
        const std::string &input);

}
}

#endif