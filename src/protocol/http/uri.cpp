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

    const std::string ut_strings[] = {
        "", 
        "http", 
        "https", 
        "ws", 
        "wss"
    };

    std::string get_ut_string(int32_t ut) {
        return ut_strings[ut];
    }

    bool parse_url(const std::string &url,
                   int32_t &ut,
                   std::string &host,
                   std::string &path,
                   std::map<std::string, std::string> &params) {
        std::string sut;
        {
            auto result = split_string(url, "[:]");
            if (result.size() >= 2) {
                sut = result[0];
            } else {
                sut = "https";
            }
        }

        const block_t *p = url.c_str();
        for (ut = URI_HTTP; ut < URI_END; ut++) {
            if (pump_strncasecmp(ut_strings[ut].c_str(), sut.c_str(), sut.size()) == 0) {
                p += ut_strings[ut].size();
                break;
            }
        }
        if (ut == URI_END) {
            return false;
        }

        if (memcmp(p, "://", 3) != 0) {
            return false;
        }
        p += 3;

        const block_t *end = strstr(p, "/");
        if (!end) {
            host.assign(p);
            path.assign("/");
            return true;
        }
        host.assign(p, end);
        p = end;

        end = strstr(p, "?");
        if (!end) {
            path.assign(p);
            return true;
        }
        path.assign(p, end);
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
      : ut_(UIR_NONE) {
    }

    uri::uri(const std::string &url) noexcept {
        parse(url);
    }

    void uri::reset() {
        ut_ = UIR_NONE;

        host_ = "";
        path_ = "";

        params_.clear();
    }

    bool uri::parse(const std::string &url) {
        return parse_url(url, ut_, host_, path_, params_);
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
        if (ut_ == UIR_NONE || ut_ == URI_END) {
            return std::string();
        }

        std::string url;
        url = get_ut_string(ut_) + "://" + host_ + path_;

        std::vector<std::string> tmps;
        for (auto p : params_) {
            tmps.push_back(p.first + "=" + p.second);
        }
        if (!tmps.empty()) {
            url += "?" + join_strings(tmps, "&");
        }

        std::string en_url;
        if (!url_encode(url, en_url)) {
            return std::string();
        }

        return en_url;
    }

}  // namespace http
}  // namespace protocol
}  // namespace pump