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

#ifndef pump_ssl_sign_h
#define pump_ssl_sign_h

#include <string>
#include <vector>

#include "pump/ssl/hash.h"

namespace pump {
namespace ssl {

    typedef uint16_t signature_algorithm;
    const signature_algorithm TLS_SIGNATURE_UNKNOWN  =  0;
	const signature_algorithm TLS_SIGNATURE_PKCS1V15 = 225;
	const signature_algorithm TLS_SIGNATURE_RSAPSS   = 256;
	const signature_algorithm TLS_SIGNATURE_ECDSA    = 257;
	const signature_algorithm TLS_SIGNATURE_ED25519  = 258;

    bool verify_signature(
            signature_algorithm sign_algo, 
            hash_algorithm hash_algo,
            void_ptr cert, 
            const std::string &msg, 
            const std::string &sign);

}
}

#endif