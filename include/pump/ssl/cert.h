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

#include "pump/ssl/hash.h"

namespace pump {
namespace ssl {

    // TLS signature algorithm
    typedef uint16_t signature_algorithm;
    const signature_algorithm TLS_SIGN_ALGO_UNKNOWN  =  0;
	const signature_algorithm TLS_SIGN_ALGO_PKCS1V15 = 225;
	const signature_algorithm TLS_SIGN_ALGO_RSAPSS   = 256;
	const signature_algorithm TLS_SIGN_ALGO_ECDSA    = 257;
	const signature_algorithm TLS_SIGN_ALGO_ED25519  = 258;

    // TLS signature scheme
    typedef uint16_t signature_scheme;
    const signature_scheme TLS_SIGN_SCHE_UNKNOWN                = 0x0000;
    // RSASSA-PKCS1-v1_5 algorithms.
    const signature_scheme TLS_SIGN_SCHE_PKCS1WITHSHA256        = 0x0401;
    const signature_scheme TLS_SIGN_SCHE_PKCS1WITHSHA384        = 0x0501;
    const signature_scheme TLS_SIGN_SCHE_PKCS1WITHSHA512        = 0x0601;
    // RSASSA-PSS algorithms with public key OID rsaEncryption.
    const signature_scheme TLS_SIGN_SCHE_PSSWITHSHA256          = 0x0804;
    const signature_scheme TLS_SIGN_SCHE_PSSWITHSHA384          = 0x0805;
    const signature_scheme TLS_SIGN_SCHE_PSSWITHSHA512          = 0x0806;
    // ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
    const signature_scheme TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256 = 0x0403;
    const signature_scheme TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384 = 0x0503;
    const signature_scheme TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512 = 0x0603;
    // EdDSA algorithms.
    const signature_scheme TLS_SIGN_SCHE_ED25519                = 0x0807;
    // Legacy signature and hash algorithms for TLS 1.2.
    const signature_scheme TLS_SIGN_SCHE_PKCS1WITHSHA1          = 0x0201;
    const signature_scheme TLS_SIGN_SCHE_ECDSAWITHSHA1          = 0x0203;

    // X509 certificate
    struct x509_certificate;

    /*********************************************************************************
     * Generate X509 certificate.
     ********************************************************************************/
    x509_certificate* generate_x509_certificate(signature_scheme scheme);

    /*********************************************************************************
     * To X509 certificate pem data.
     ********************************************************************************/
    bool to_x509_certificate_pem(x509_certificate *xcert, std::string &pem);

    /*********************************************************************************
     * To X509 certificate bin data.
     ********************************************************************************/
    bool to_x509_certificate_bin(x509_certificate *xcert, std::string &bin);

    /*********************************************************************************
     * Load X509 certificate by pem.
     ********************************************************************************/
    x509_certificate* load_x509_certificate_by_pem(
        const std::string &cert, 
        const std::string &key);
    x509_certificate* load_x509_certificate_by_pem(
        const block_t *cert, 
        int32_t cert_size,
        const block_t *key, 
        int32_t key_size);

    /*********************************************************************************
     * Load X509 certificate by raw.
     ********************************************************************************/
    x509_certificate* load_x509_certificate_by_bin(
        const std::string &cert,
        const std::string &key);
    x509_certificate* load_x509_certificate_by_bin(
        const block_t *cert, 
        int32_t cert_size,
        const block_t *key, 
        int32_t key_size);

    /*********************************************************************************
     * Free X509 certificate.
     ********************************************************************************/
    void free_x509_certificate(x509_certificate *xcert);

    /*********************************************************************************
     * X509 certificate verify.
     ********************************************************************************/
    bool verify_x509_certificates(std::vector<x509_certificate*> &xcerts);

    /*********************************************************************************
     * Check X509 certificate scts exists or not.
     ********************************************************************************/
    bool has_x509_scts(x509_certificate *xcert);

    /*********************************************************************************
     * Get X509 certificate scts.
     ********************************************************************************/
    bool get_x509_scts(x509_certificate *xcert, std::vector<std::string> &scts);

    /*********************************************************************************
     * Get X509 certificate signature scheme.
     ********************************************************************************/
    signature_scheme get_x509_signature_scheme(x509_certificate *xcert);

    /*********************************************************************************
     * Do X509 signature.
     ********************************************************************************/
    bool do_x509_signature(
        x509_certificate *xcert, 
        signature_algorithm sign_algo, 
        hash_algorithm hash_algo,
        const std::string &msg,
        std::string &sign);

    /*********************************************************************************
     * Verify X509 signature.
     ********************************************************************************/
    bool verify_x509_signature(
        x509_certificate *xcert, 
        signature_algorithm sign_algo, 
        hash_algorithm hash_algo,            
        const std::string &msg, 
        const std::string &sign);

}  // namespace ssl
}  // namespace pump

#endif