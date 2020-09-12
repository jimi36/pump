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

#include "pump/protocol/http/header.h"
#include "pump/protocol/http/defines.h"

namespace pump {
namespace protocol {
    namespace http {

#define HEAD_VALUE_SEP "; "

        header::header() noexcept : parse_finished_(false) {
        }

        int32 header::parse(c_block_ptr b, int32 size) {
            if (parse_finished_)
                return 0;

            c_block_ptr beg = b;
            c_block_ptr end = b;

            uint32 len = 0;
            std::string name;
            std::string value;
            c_block_ptr line_end = nullptr;
            while ((line_end = find_http_line_end(beg, uint32(size - (end - b))))) {
                // parse header finished
                if (beg + HTTP_CR_LEN == line_end) {
                    beg += HTTP_CR_LEN;
                    parse_finished_ = true;
                    break;
                }

                // parse header name
                while (end < line_end && *end != ':')
                    ++end;
                len = (uint32)(end - beg);
                if (end >= line_end || len <= 0)
                    return -1;
                name.assign(beg, len);
                ++end;

                // seek ':' and ' '
                while (end < line_end && (*end == ' '))
                    ++end;
                if (end >= line_end - HTTP_CR_LEN)
                    return -1;

                // parse header value
                beg = end;
                end = line_end - 2;
                len = (uint32)(end - beg);
                if (len == 0)
                    return -1;
                value.assign(beg, len);

                set(name, value);

                beg = end = line_end;
            }

            return (int32)(beg - b);
        }

        int32 header::serialize(std::string &buffer) const {
            int32 size = 0;
            std::string value;
            block tmp[HTTP_LINE_MAX_LEN] = {0};
            for (auto beg = headers_.begin(); beg != headers_.end(); beg++) {
                auto cnt = beg->second.size();
                if (cnt == 0)
                    continue;
                else if (cnt == 1)
                    value = beg->second[0];
                else
                    value = join_strings(beg->second, HEAD_VALUE_SEP);

                size += pump_snprintf(
                    tmp, sizeof(tmp), "%s: %s\r\n", beg->first.c_str(), value.c_str());
                buffer.append(tmp);
            }

            size += HTTP_CR_LEN;
            buffer.append(HTTP_CR);

            return size;
        }

        void header::set(const std::string &name, int32 value) {
            block tmp[32] = {0};
            pump_snprintf(tmp, sizeof(tmp) - 1, "%d", value);
            auto it = headers_.find(name);
            if (it == headers_.end())
                headers_[name].push_back(tmp);
            else
                it->second.push_back(tmp);
        }

        void header::set(const std::string &name, const std::string &value) {
            auto vals = split_string(value, "[,;] *");
            auto it = headers_.find(name);
            if (it == headers_.end())
                headers_[name] = vals;
            else
                it->second.insert(it->second.end(), vals.begin(), vals.end());
        }

        void header::set_unique(const std::string &name, int32 value) {
            block tmp[32] = {0};
            pump_snprintf(tmp, sizeof(tmp) - 1, "%d", value);
            headers_[name] = std::vector<std::string>(1, tmp);
        }

        void header::set_unique(const std::string &name, const std::string &value) {
            headers_[name] = split_string(value, "[,;] *");
        }

        bool header::get(const std::string &name, int32 &value) const {
            auto it = headers_.find(name);
            if (it == headers_.end())
                return false;

            if (it->second.empty())
                return false;

            value = atol(it->second[0].c_str());

            return true;
        }

        bool header::get(const std::string &name, std::string &value) const {
            auto it = headers_.find(name);
            if (it == headers_.end())
                return false;

            if (it->second.empty())
                return false;

            value = join_strings(it->second, HEAD_VALUE_SEP);

            return true;
        }

        bool header::get(const std::string &name,
                         std::vector<std::string> &values) const {
            auto it = headers_.find(name);
            if (it == headers_.end())
                return false;

            if (it->second.empty())
                return false;

            values = it->second;

            return true;
        }

        bool header::has(const std::string &name) const {
            if (headers_.find(name) == headers_.end())
                return false;
            return true;
        }

    }  // namespace http
}  // namespace protocol
}  // namespace pump