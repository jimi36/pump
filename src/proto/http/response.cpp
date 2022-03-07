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

#include <unordered_map>

#include "pump/debug.h"
#include "pump/memory.h"
#include "pump/proto/http/response.h"

namespace pump {
namespace proto {
namespace http {

static std::unordered_map<int32_t, std::string> http_code_desc_map;

static void init_http_code_desc_map() {
    static bool inited = false;
    if (inited) {
        return;
    }
    inited = true;

    http_code_desc_map[0] = "";
    http_code_desc_map[100] = "Continue";
    http_code_desc_map[101] = "Switching protos";
    http_code_desc_map[200] = "OK";
    http_code_desc_map[201] = "Created";
    http_code_desc_map[202] = "Accepted";
    http_code_desc_map[203] = "Non-Authoritative Information";
    http_code_desc_map[204] = "No Content";
    http_code_desc_map[205] = "Reset Content";
    http_code_desc_map[206] = "Partial Content";
    http_code_desc_map[300] = "Multiple Choices";
    http_code_desc_map[301] = "Moved Permanently";
    http_code_desc_map[302] = "Found";
    http_code_desc_map[303] = "See Other";
    http_code_desc_map[304] = "Not Modified";
    http_code_desc_map[305] = "Use Proxy";
    http_code_desc_map[307] = "Temporary Redirect";
    http_code_desc_map[400] = "Bad Request";
    http_code_desc_map[401] = "Unauthorized";
    http_code_desc_map[403] = "Forbidden";
    http_code_desc_map[404] = "Not Found";
    http_code_desc_map[405] = "Method Not Allowed";
    http_code_desc_map[406] = "Not Acceptable";
    http_code_desc_map[407] = "Proxy Authentication Required";
    http_code_desc_map[408] = "Request Timeout";
    http_code_desc_map[409] = "Conflict";
    http_code_desc_map[410] = "Gone";
    http_code_desc_map[411] = "Length Required";
    http_code_desc_map[412] = "Precondition Failed";
    http_code_desc_map[413] = "Request Entity Too Large";
    http_code_desc_map[414] = "Request URI Too Long";
    http_code_desc_map[416] = "Requested Range Not Satisfiable";
    http_code_desc_map[500] = "Internal Server Error";
    http_code_desc_map[501] = "Not Implemented";
    http_code_desc_map[502] = "Bad Gateway";
    http_code_desc_map[503] = "Service Unavailable";
    http_code_desc_map[504] = "Gateway Timeout";
    http_code_desc_map[505] = "HTTP Version Not Supported";
}

static const std::string &get_http_code_desc(int32_t code) {
    auto it = http_code_desc_map.find(code);
    if (it != http_code_desc_map.end()) {
        return it->second;
    }
    return http_code_desc_map[0];
}

response::response(void *ctx) noexcept :
    packet(ctx, PK_RESPONSE), status_code_(0) {
    init_http_code_desc_map();
}

int32_t response::parse(const char *b, int32_t size) {
    if (parse_status_ == PARSE_FINISHED) {
        return 0;
    }

    if (parse_status_ == PARSE_NONE) {
        parse_status_ = PARSE_LINE;
    }

    const char *pos = b;
    int32_t parse_size = 0;
    if (parse_status_ == PARSE_LINE) {
        parse_size = __parse_start_line(pos, size);
        if (parse_size <= 0) {
            return parse_size;
        }

        pos += parse_size;
        size -= parse_size;

        parse_status_ = PARSE_HEADER;
    }

    if (parse_status_ == PARSE_HEADER) {
        parse_size = __parse_header(pos, size);
        if (parse_size < 0) {
            pump_warn_log("parse response header failed");
            return -1;
        } else if (parse_size == 0) {
            return int32_t(pos - b);
        }

        pos += parse_size;
        size -= parse_size;

        if (!__is_header_parsed()) {
            return int32_t(pos - b);
        }

        int32_t length = 0;
        if (get_head("Content-Length", length) ||
            get_head("content-length", length)) {
            if (length > 0) {
                body_.reset(object_create<body>(), object_delete<body>);
                if (!body_) {
                    pump_warn_log("new response body object failed");
                    return -1;
                }
                body_->set_expected_size(length);
            }
        } else {
            std::string transfer_encoding;
            if (get_head("Transfer-Encoding", transfer_encoding) ||
                get_head("transfer-encoding", transfer_encoding)) {
                if (transfer_encoding == "chunked") {
                    body_.reset(object_create<body>(), object_delete<body>);
                    if (!body_) {
                        pump_warn_log("new response chunk body object failed");
                        return -1;
                    }
                    body_->set_chunked();
                }
            }
        }

        if (body_) {
            parse_status_ = PARSE_BODY;
        } else {
            parse_status_ = PARSE_FINISHED;
        }
    }

    if (parse_status_ == PARSE_BODY) {
        pump_assert(body_);
        if ((parse_size = body_->parse(pos, size)) < 0) {
            pump_warn_log("parse response body failed");
            return -1;
        }

        pos += parse_size;
        size -= parse_size;

        if (body_->is_parse_finished()) {
            parse_status_ = PARSE_FINISHED;
        }
    }

    return int32_t(pos - b);
}

int32_t response::serialize(std::string &buffer) const {
    int32_t serialize_size = 0;

    int32_t size = __serialize_response_line(buffer);
    if (size < 0) {
        pump_warn_log("serialize response line failed");
        return -1;
    }
    serialize_size += size;

    size = __serialize_header(buffer);
    if (size < 0) {
        pump_warn_log("serialize response header failed");
        return -1;
    }
    serialize_size += size;

    if (body_) {
        size = body_->serialize(buffer);
        if (size < 0) {
            pump_warn_log("serialize response body failed");
            return -1;
        }
        serialize_size += size;
    }

    return serialize_size;
}

int32_t response::__parse_start_line(const char *b, int32_t size) {
    const char *pos = b;

    const char *line_end = find_http_line_end(pos, size);
    if (line_end == nullptr) {
        return 0;
    }

    // Parse response version
    if (strncmp(pos, "HTTP/1.0", 8) == 0) {
        version_ = VERSION_10;
    } else if (strncmp(pos, "HTTP/1.1", 8) == 0) {
        version_ = VERSION_11;
    } else if (strncmp(pos, "HTTP/2.0", 8) == 0) {
        version_ = VERSION_20;
    } else {
        pump_warn_log("parse response http version failed");
        return -1;
    }
    pos += 8;

    // Parse response code
    while (pos < line_end && *pos == ' ') {
        ++pos;
    }
    while (pos < line_end && *pos != ' ') {
        status_code_ = status_code_ * 10 + int32_t(*(pos++) - '0');
    }
    if (pos == line_end) {
        pump_warn_log("parse response code failed");
        return -1;
    }

    return int32_t(line_end - b);
}

int32_t response::__serialize_response_line(std::string &buffer) const {
    char tmp[128] = {0};
    int32_t size = pump_snprintf(
        tmp,
        sizeof(tmp) - 1,
        "%s %d %s\r\n",
        get_http_version_string().c_str(),
        status_code_,
        get_http_code_desc(status_code_).c_str());
    buffer.append(tmp);
    return size;
}

}  // namespace http
}  // namespace proto
}  // namespace pump
