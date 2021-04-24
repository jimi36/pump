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

#include "pump/utils.h"
#include "pump/protocol/http/uri.h"

namespace pump {
namespace protocol {
namespace http {

    const std::vector<std::string> uri_protocol_names = {
        "", 
        "http", 
        "https", 
        "ws", 
        "wss"
    };

    const std::string& get_uri_protocol_name(uri_protocol uc) {
        return uri_protocol_names[uc];
    }

    bool parse_url(
        const std::string &url,
        uri_protocol &proto,
        std::string &host,
        std::string &path,
        std::map<std::string, std::string> &params) {
        std::string proto_name;
        {
            auto result = split_string(url, "[:]");
            if (result.size() >= 2) {
                proto_name = result[0];
            } else {
                proto_name = "https";
            }
        }

        const block_t *p = url.c_str();
        for (proto = URI_HTTP; proto < URI_END; proto++) {
            const std::string &name = get_uri_protocol_name(proto);
            if (pump_strncasecmp(
                    name.c_str(), 
                    proto_name.c_str(), 
                    proto_name.size()) == 0) {
                p += name.size();
                break;
            }
        }
        if (proto == URI_END) {
            proto = UIR_UNKNOWN;
            return false;
        }

        if (memcmp(p, "://", 3) != 0) {
            return false;
        }
        p += 3;

        const block_t *end = strstr(p, "/");
        if (end == nullptr) {
            host.assign(p);
            path.assign("/");
            return true;
        } else {
            host.assign(p, end);
        }
        p = end;

        end = strstr(p, "?");
        if (end == nullptr) {
            path.assign(p);
            return true;
        } else {
            path.assign(p, end);
        }
        p = end + 1;

        std::string new_params;
        std::string raw_params(p);
        if (!url_decode(raw_params, new_params)) {
            return false;
        }
        auto kvs = split_string(new_params, "[=&]");
        uint32_t cnt = (uint32_t)kvs.size();
        if (cnt % 2 != 0) {
            return false;
        }
        for (uint32_t i = 0; i < cnt; i += 2) {
            params[kvs[i]] = kvs[i + 1];
        }

        return true;
    }

    uri::uri() noexcept
      : proto_(UIR_UNKNOWN) {
    }

    uri::uri(const std::string &url) noexcept {
        parse(url);
    }

    void uri::reset() {
        proto_ = UIR_UNKNOWN;
        params_.clear();
        host_.clear();
        path_.clear();
    }

    bool uri::parse(const std::string &url) {
        return parse_url(url, proto_, host_, path_, params_);
    }

    bool uri::get_param(
        const std::string &key, 
        std::string &value) const {
        auto it = params_.find(key);
        if (it == params_.end()) {
            return false;
        }
        value = it->second;
        return true;
    }

    std::string uri::to_url() const {
        if (proto_ <= UIR_UNKNOWN || proto_ >= URI_END) {
            return std::string();
        }

        std::string raw_url;
        raw_url = get_uri_protocol_name(proto_) + "://" + host_ + path_;

        std::vector<std::string> param_val;
        for (auto p : params_) {
            param_val.push_back(p.first + "=" + p.second);
        }
        if (!param_val.empty()) {
            raw_url += "?" + join_strings(param_val, "&");
        }

        std::string url;
        if (!url_encode(raw_url, url)) {
            return std::string();
        }

        return url;
    }

}  // namespace http
}  // namespace protocol
}  // namespace pump