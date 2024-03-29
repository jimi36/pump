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

#include "pump/debug.h"
#include "pump/codec/sha1.h"
#include "pump/codec/base64.h"
#include "pump/proto/http/utils.h"

namespace pump {
namespace proto {
namespace http {

const char *find_http_line_end(const char *src, int32_t len) {
    len = std::min<int32_t>(len, http_line_max_length);
    if (len < http_line_min_length) {
        return nullptr;
    }

    while (len >= http_crlf_length) {
        if (*src == '\r') {
            if (*(src + 1) == '\n') {
                src += http_crlf_length;
                return src;
            }
            return nullptr;
        }
        len--;
        src++;
    }

    return nullptr;
}

bool url_decode(const std::string &src, std::string &des) {
    auto len = (uint32_t)src.length();
    for (uint32_t i = 0; i < len; i++) {
        char ch = src[i];
        if (ch == '+') {
            ch = ' ';
        } else if (ch == '%') {
            if (i + 2 >= len) {
                return false;
            }
            ch = hex_to_dec(src[i + 1]) << 4 | hex_to_dec(src[i + 2]);
            i += 2;
        }
        des.append(1, ch);
    }
    return true;
}

bool url_encode(const std::string &src, std::string &des) {
    auto beg = src.c_str();
    auto end = beg + src.size();
    while (beg != end) {
        char val = *beg;
        if (isalnum(val) || strchr("_-.", val) != nullptr) {
            des.append(1, val);
        } else if (val == ' ') {
            des.append(1, '+');
        } else {
            des.append(1, '%');
            des.append(1, dec_to_hex(val >> 4));
            des.append(1, dec_to_hex(val & 0x0f));
        }
        ++beg;
    }
    return true;
}

std::string compute_sec_key() {
    std::string s(16, 0);
    auto *p = (int32_t *)s.data();
    for (uint32_t i = 0; i < 4; i++) {
        *(p + i) = random();
    }
    return codec::base64_encode(s);
}

std::string compute_sec_accept_key(const std::string &sec_key) {
    std::string hash(20, 0);
    std::string tmp = sec_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    codec::sha1(tmp.c_str(), (uint32_t)tmp.size(), (uint8_t *)hash.c_str());
    return codec::base64_encode(hash);
}

}  // namespace http
}  // namespace proto
}  // namespace pump