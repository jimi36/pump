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

#ifndef pump_ssl_cert_h
#define pump_ssl_cert_h

#include <string>
#include <vector>

#include "pump/types.h"

namespace pump {
namespace ssl {

    /*********************************************************************************
     * Load X509 certificate.
     ********************************************************************************/
    void_ptr load_x509_certificate(void_ptr data, int32_t size);

    /*********************************************************************************
     * Free X509 certificate.
     ********************************************************************************/
    void free_x509_certificate(void_ptr cert);

    /*********************************************************************************
     * X509 certificate verify.
     ********************************************************************************/
    bool verify_x509_certificates(std::vector<void_ptr> &certs);

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