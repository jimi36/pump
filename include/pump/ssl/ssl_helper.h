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

#ifndef pump_ssl_ssl_helper_h
#define pump_ssl_ssl_helper_h

#include <string>

#include "pump/types.h"

namespace pump {
namespace ssl {

    typedef int64_t hash_algorithm;
    //const hash_algorithm HASH_SHA1 = 1;
    //const hash_algorithm HASH_SHA128 = 2;
    //const hash_algorithm HASH_SHA224 = 3;
    const hash_algorithm HASH_SHA256 = 4;
    const hash_algorithm HASH_SHA384 = 5;
    //const hash_algorithm HASH_SHA512 = 6;

    class hasher {
      public:
        /*********************************************************************************
         * Constructor
         ********************************************************************************/
        hasher(hash_algorithm algorithm);

        /*********************************************************************************
         * Deconstructor
         ********************************************************************************/
        ~hasher();

        /*********************************************************************************
         * Update with data
         ********************************************************************************/
        bool update(void_ptr data, int32_t data_len);

        /*********************************************************************************
         * Get hash result
         ********************************************************************************/
        bool result(std::string &hash);

      private:
        // Hash context 
        void_ptr hash_ctx_;
        // Hash result length
        int32_t result_length_;
        // Hash algorithm
        hash_algorithm algorithm_;
    };

    /*********************************************************************************
     * Create tls client certificate.
     ********************************************************************************/
    void_ptr create_tls_client_certificate();

    /*********************************************************************************
     * Create tls certificate by file.
     ********************************************************************************/
    void_ptr create_tls_certificate_by_file(bool client,
                                            const std::string &cert,
                                            const std::string &key);

    /*********************************************************************************
     * Create tls certificate by buffer.
     ********************************************************************************/
    void_ptr create_tls_certificate_by_buffer(bool client,
                                              const std::string &cert,
                                              const std::string &key);

    /*********************************************************************************
     * Destory tls certificate.
     ********************************************************************************/
    void destory_tls_certificate(void_ptr xcred);

    /*********************************************************************************
     * ECDHE crypto key pair.
     ********************************************************************************/
    struct ecdhe_key_pair {
        std::string prikey;
        std::string pubkey;
    };

    /*********************************************************************************
     * Generate X25519 key pair.
     ********************************************************************************/
    bool generate_X25519_key_pair(ecdhe_key_pair *kp);

}  // namespace ssl
}  // namespace pump

#endif