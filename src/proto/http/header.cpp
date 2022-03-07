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
#include "pump/proto/http/header.h"

namespace pump {
namespace proto {
namespace http {

#define head_value_sep "; "

header::header() noexcept :
    header_parsed_(false) {}

void header::set_head(const std::string &name, int32_t value) {
    char strval[64] = {0};
    pump_snprintf(strval, sizeof(strval) - 1, "%d", value);
    headers_[name].push_back(strval);
}

void header::set_head(const std::string &name, const std::string &value) {
    auto vals = split_string(value, "[,;] *");
    auto it = headers_.find(name);
    if (it == headers_.end()) {
        headers_[name] = vals;
    } else {
        it->second.insert(it->second.end(), vals.begin(), vals.end());
    }
}

void header::set_unique_head(const std::string &name, int32_t value) {
    char strval[64] = {0};
    pump_snprintf(strval, sizeof(strval) - 1, "%d", value);
    headers_[name] = std::vector<std::string>(1, strval);
}

void header::set_unique_head(
    const std::string &name,
    const std::string &value) {
    headers_[name] = split_string(value, "[,;] *");
}

bool header::get_head(const std::string &name, int32_t &value) const {
    auto it = headers_.find(name);
    if (it == headers_.end() || it->second.empty()) {
        return false;
    }
    value = atol(it->second[0].c_str());
    return true;
}

bool header::get_head(const std::string &name, std::string &value) const {
    auto it = headers_.find(name);
    if (it == headers_.end() || it->second.empty()) {
        return false;
    }
    value = join_strings(it->second, head_value_sep);
    return true;
}

bool header::get_head(
    const std::string &name,
    std::vector<std::string> &values) const {
    auto it = headers_.find(name);
    if (it == headers_.end() || it->second.empty()) {
        return false;
    }
    values = it->second;
    return true;
}

bool header::has_head(const std::string &name) const {
    if (headers_.find(name) == headers_.end()) {
        return false;
    }
    return true;
}

int32_t header::__parse_header(const char *b, int32_t size) {
    if (header_parsed_) {
        return 0;
    }

    std::string name;
    std::string value;
    const char *beg = b;
    const char *end = b;
    const char *line_end = nullptr;
    while ((line_end = find_http_line_end(beg, uint32_t(size - (end - b))))) {
        // Check parsed complete
        if (beg + http_crlf_length == line_end) {
            beg += http_crlf_length;
            header_parsed_ = true;
            break;
        }

        // Parse header name
        while (end < line_end && *end != ':') {
            ++end;
        }
        if (end >= line_end || end == beg) {
            return -1;
        }
        name.assign(beg, end);

        // Skip to header vaule position
        while (end < line_end && (*end == ' ' || *end == ':')) {
            ++end;
        }
        pump_assert(end <= line_end - http_crlf_length);

        // Parse header value
        beg = end;
        end = line_end - http_crlf_length;
        if (end > beg) {
            value.assign(beg, end);
        }

        // Store header
        set_head(name, value);

        beg = end = line_end;
    }

    return int32_t(beg - b);
}

int32_t header::__serialize_header(std::string &buffer) const {
    int32_t size = 0;
    std::string value;
    char header_line[http_line_max_length + 1] = {0};
    for (auto beg = headers_.begin(); beg != headers_.end(); beg++) {
        auto cnt = beg->second.size();
        if (cnt == 0) {
            continue;
        } else if (cnt == 1) {
            value = beg->second[0];
        } else {
            value = join_strings(beg->second, head_value_sep);
        }
        size += pump_snprintf(
            header_line,
            sizeof(header_line) - 1,
            "%s: %s\r\n",
            beg->first.c_str(),
            value.c_str());
        buffer.append(header_line);
    }

    size += http_crlf_length;
    buffer.append(http_crlf);

    return size;
}

}  // namespace http
}  // namespace proto
}  // namespace pump