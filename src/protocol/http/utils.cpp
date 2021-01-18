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
#include "pump/protocol/http/utils.h"

namespace pump {
namespace protocol {
    namespace http {

        const block_t* find_http_line_end(const block_t *src, int32_t len) {
            len = std::min<int32_t>(len, HTTP_LINE_MAX_LEN);
            if (len < HTTP_LINE_MIN_LEN) {
                return nullptr;
            }

            while (len >= HTTP_CR_LEN) {
                if (*src == '\r') {
                    if (*(src + 1) == '\n') {
                        src += HTTP_CR_LEN;
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
            uint32_t len = (uint32_t)src.length();
            for (uint32_t i = 0; i < len; i++) {
                uint8_t ch = src[i];
                if (ch == '+') {
                    ch = ' ';
                } else if (ch == '%') {
                    if (i + 2 >= len)
                        return false;
                    ch = hexchar_to_decnum(src[i + 1]) << 4 |
                         hexchar_to_decnum(src[i + 2]);
                    i += 2;
                }
                des.append(1, (block_t)ch);
            }
            return true;
        }

        bool url_encode(const std::string &src, std::string &des) {
            uint8_t val = 0;
            const block_t *beg = src.c_str();
            const block_t *end = beg + src.size();
            while (beg != end) {
                val = uint8_t(*beg);
                if (isalnum(val) || (val == '-') || (val == '_') || (val == '.') || (val == '~')) {
                    des.append(1, val);
                } else if (*beg == ' ') {
                    des.append(1, '+');
                } else {
                    des.append(1, '%');
                    des.append(1, decnum_to_hexchar(val >> 4));
                    des.append(1, decnum_to_hexchar(val % 16));
                }
                ++beg;
            }
            return true;
        }

        transport::address host_to_address(bool https, const std::string &host) {
            auto results = split_string(host, "[:]");
            if (results.empty()) {
                PUMP_ASSERT(false);
            }

            uint16_t port = https ? 443 : 80;
            if (results.size() > 1) {
                port = atoi(results[1].c_str());
            }

            return transport::address(results[0], port);
        }

    }  // namespace http
}  // namespace protocol
}  // namespace pump