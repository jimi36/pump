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
#include <vector>

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

    struct hash_context;
    DEFINE_ALL_POINTER_TYPE(hash_context);

    /*********************************************************************************
     * Hash size.
      ********************************************************************************/
    int32_t hash_size(hash_algorithm algorithm);

    /*********************************************************************************
     * Hash new
     ********************************************************************************/
    hash_context_ptr hash_new(hash_algorithm algorithm);

    /*********************************************************************************
     * Hash delete
     ********************************************************************************/
    void hash_delete(hash_context_ptr ctx);

    /*********************************************************************************
     * Hash update
     ********************************************************************************/
    bool hash_update(hash_context_ptr ctx, const void_ptr data, int32_t data_len);

    /*********************************************************************************
     * Hash result
     ********************************************************************************/
    bool hash_result(hash_context_ptr ctx, void_ptr out, int32_t out_len);

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

    /*********************************************************************************
     * HKDF extract.
     ********************************************************************************/
    bool hkdf_extract(hash_algorithm algorithm, 
                      const std::string &salt,
                      const std::string &key,
                      std::string &out);

    /*********************************************************************************
     * HKDF expand.
     ********************************************************************************/
    bool hkdf_expand(hash_algorithm algorithm, 
                     const std::string &key,
                     const std::string &info,
                     std::string &out);

    /*********************************************************************************
     * X509 certificate new.
     ********************************************************************************/
    void_ptr x509_certificate_new(void_ptr data, int32_t size);

    /*********************************************************************************
     * X509 certificate delete.
     ********************************************************************************/
    void x509_certificate_delete(void_ptr cert);

    /*********************************************************************************
     * X509 certificate verify.
     ********************************************************************************/
    bool x509_certificate_verify(std::vector<void_ptr> &certs);

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

}  // namespace ssl
}  // namespace pump

#endif