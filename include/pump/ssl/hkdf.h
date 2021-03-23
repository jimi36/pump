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

#ifndef pump_ssl_hkdf_h
#define pump_ssl_hkdf_h

#include <string>

#include "pump/ssl/hash.h"

namespace pump {
namespace ssl {

    /*********************************************************************************
     * HKDF extract.
     ********************************************************************************/
    bool hkdf_extract(hash_algorithm algo, 
                      const std::string &salt,
                      const std::string &key,
                      std::string &out);

    /*********************************************************************************
     * HKDF expand.
     ********************************************************************************/
    bool hkdf_expand(hash_algorithm algo, 
                     const std::string &key,
                     const std::string &info,
                     std::string &out);

}
}