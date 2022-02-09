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

#include <regex>

#include "pump/debug.h"
#include "pump/utils.h"
#include "pump/proto/http/uri.h"

namespace pump {
namespace proto {
namespace http {

/*
bool parse_url(
const std::string &url,
uri_type &proto,
std::string &host,
std::string &path,
std::map<std::string, std::string> &params) {
{
    auto result = split_string(url, "[:]");
    if (result.size() >= 2) {
        proto = result[0];
    } else {
        proto = URI_HTTP;
    }
}

const block_t *p = url.c_str();
for (proto = URI_HTTP; proto < URI_END; proto++) {
    const std::string &name = get_uri_proto_name(proto);
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
    PUMP_WARN_LOG("url type unknown");
    return false;
}

if (memcmp(p, "://", 3) == 0) {
    p += 3;
}

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
    PUMP_WARN_LOG("url params url decode failed");
    return false;
}
auto kvs = split_string(new_params, "[=&]");
uint32_t cnt = (uint32_t)kvs.size();
if (cnt % 2 != 0) {
    PUMP_WARN_LOG("url params invalid");
    return false;
}
for (uint32_t i = 0; i < cnt; i += 2) {
    params[kvs[i]] = kvs[i + 1];
}

return true;
}
*/

uri::uri() noexcept : tp_(URI_END) {}

uri::uri(const std::string &url) noexcept {
    parse(url);
}

void uri::reset() {
    tp_ = URI_END;
    params_.clear();
    host_.clear();
    path_.clear();
}

bool uri::parse(const std::string &url) {
    const static std::string reg_proto = "((https?|HTTPS?|wss?|WSS?)://)?";
    const static std::string reg_host = "([-\\w~@#$%&+=|.]+(:[\\d]{0,5})?)";
    const static std::string reg_path = "(/[-\\w~@#$%&+=|./]*)?";
    const static std::string reg_param = "(\\?([\\w~!@#$%&+=|:;,.]*))?";
    const static std::string reg = reg_proto + reg_host + reg_path + reg_param;
    const static std::regex partten(reg.c_str());

    std::smatch sm;
    if (!std::regex_match(url.cbegin(), url.cend(), sm, partten)) {
        return false;
    }

    // uri type
    if (sm[2].matched) {
        tp_ = sm[2].str();
        std::transform(tp_.begin(), tp_.end(), tp_.begin(), ::tolower);
    } else {
        tp_ = URI_HTTP;
    }

    // uri host
    if (!sm[3].matched) {
        return false;
    }
    host_ = sm[3].str();

    // uri path
    if (sm[5].matched) {
        path_ = sm[5].str();
    } else {
        path_ = "/";
    }

    // uri params
    if (sm[6].matched) {
        std::string new_params;
        if (!url_decode(sm[6].str(), new_params)) {
            PUMP_WARN_LOG("url params url decode failed");
            return false;
        }
        auto kvs = split_string(new_params, "[=&]");
        uint32_t cnt = (uint32_t)kvs.size();
        if (cnt % 2 != 0) {
            PUMP_WARN_LOG("url params is invalid");
            return false;
        }
        for (uint32_t i = 0; i < cnt; i += 2) {
            params_[kvs[i]] = kvs[i + 1];
        }
    }

    return true;
}

bool uri::get_param(const std::string &key, std::string &value) const {
    auto it = params_.find(key);
    if (it == params_.end()) {
        return false;
    }
    value = it->second;
    return true;
}

std::string uri::to_url() const {
    if (tp_ == URI_END) {
        return std::string();
    }

    std::string url(tp_ + "://" + host_ + path_);

    std::vector<std::string> param_val;
    for (auto p : params_) {
        param_val.push_back(p.first + "=" + p.second);
    }
    if (!param_val.empty()) {
        url += "?" + join_strings(param_val, "&");
    }

    return url;
}

address uri::to_address() const {
    auto results = split_string(host_, "[:]");
    if (results.empty()) {
        return address();
    }

    uint16_t port = 80;
    if (results.size() > 1) {
        port = atoi(results[1].c_str());
    } else if (tp_ == URI_HTTPS || tp_ == URI_WSS) {
        port = 443;
    }

    return address(results[0], port);
}

}  // namespace http
}  // namespace proto
}  // namespace pump