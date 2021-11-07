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

#include <regex>

#if defined(HAVE_ICONV_HEADER)
#include <iconv.h>
#endif

namespace pump {

    uint8_t dec_to_hex(uint8_t dec) {
        if (dec >= 0 && dec <= 9) {
            return uint8_t('0') + dec;
        } else if (dec >= 10 && dec <= 15) {
            return uint8_t('A') + dec - 10;
        }
        return 0;
    }

    uint8_t hex_to_dec(uint8_t hex) {
        if (hex >= '0' && hex <= '9') {
            return uint8_t(hex - '0');
        } else if (hex >= 'a' && hex <= 'f') {
            return (uint8_t(hex - 'a') + 10);
        } else if (hex >= 'A' && hex <= 'F') {
            return (uint8_t(hex - 'A') + 10);
        }
        return 0;
    }

    uint16_t transform_endian(uint16_t val) {
        return (val >> 8) | (val << 8);
    }

    uint32_t transform_endian(uint32_t val) {
        return ((val >> 24) & 0x000000ff) | 
            ((val >> 8)  & 0x0000ff00) |
            ((val << 8)  & 0x00ff0000) |
            ((val << 24) & 0xff000000);
    }

    uint64_t transform_endian(uint64_t val) {
        return ((val >> 56) & 0x00000000000000ff) |
            ((val >> 40) & 0x000000000000ff00) |
            ((val >> 24) & 0x0000000000ff0000) |
            ((val >> 8)  & 0x00000000ff000000) |
            ((val << 8)  & 0x000000ff00000000) |
            ((val << 24) & 0x0000ff0000000000) |
            ((val << 40) & 0x00ff000000000000) |
            ((val << 56) & 0xff00000000000000);
    }

    int32_t ceil_to_power_of_two(int32_t val) {
        // From http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
        --val;
        val |= val >> 1;
        val |= val >> 2;
        val |= val >> 4;
        for (uint32_t i = 1; i < sizeof(int32_t); i <<= 1) {
            val |= val >> (i << 3);
        }
        ++val;
        return val;
    }

    int32_t random() {
        static std::default_random_engine e;
        return e();
    }

    std::string gbk_to_utf8(const std::string &in) {
        std::string out;
#if !defined(HAVE_ICONV_HEADER)
        std::wstring wstr(
            MultiByteToWideChar(CP_ACP, 0, in.c_str(), -1, NULL, 0) - 1, wchar_t(0));
        MultiByteToWideChar(CP_ACP, 0, in.c_str(), -1, (wchar_t*)wstr.data(), (int32_t)wstr.size());

        std::string str(
            WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)wstr.data(), -1, NULL, 0, NULL, NULL) - 1, char(0));
        WideCharToMultiByte(CP_UTF8,0, (wchar_t*)wstr.data(), -1, (char*)str.data(), (int32_t)str.size(), NULL, NULL);

        out.append(str.data(), str.size());
#else
        iconv_t cd = iconv_open("utf-8", "gb2312");
        if (cd != (iconv_t)-1) {
            size_t inlen = in.size();
            block_t *psrc = (block_t*)in.data();

            size_t outlen = inlen * 3 + 1;
            out.resize(outlen, 0);
            block_t *pdes = (block_t*)out.data();

            iconv(cd, &psrc, &inlen, &pdes, &outlen);
            out.reserve(outlen);

            iconv_close(cd);
        }

#endif
        return std::forward<std::string>(out);
    }

    std::string utf8_to_gbk(const std::string &in) {
        std::string out;
#if !defined(HAVE_ICONV_HEADER)
        std::wstring wstr(
            MultiByteToWideChar(CP_UTF8, 0, in.c_str(), -1, NULL, 0),wchar_t(0));
        MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)in.c_str(), -1, (wchar_t*)wstr.data(), (int32_t)wstr.size() - 1);

        std::string str(
            WideCharToMultiByte(CP_ACP, 0, wstr.data(), -1, NULL, 0, NULL, NULL), 0);
        WideCharToMultiByte(CP_ACP, 0, wstr.data(), -1, (char*)str.data(), (int32_t)str.size() - 1, NULL, NULL);

        out.append(str.data(), str.size() - 1);
#else
        iconv_t cd = iconv_open("gb2312", "utf-8");
        if (cd != (iconv_t)-1) {
            size_t inlen = in.size();
            block_t *psrc = (block_t*)in.c_str();

            size_t outlen = inlen * 3 + 1;
            out.resize(outlen, 0);
            block_t *pdes = (block_t*)out.c_str();

            iconv(cd, &psrc, &inlen, &pdes, &outlen);
            out.reserve(outlen);

            iconv_close(cd);
        }
#endif
        return std::forward<std::string>(out);
    }

    std::string join_strings(
        const std::vector<std::string> &src, 
        const std::string &sep) {
        std::string out;

        if (src.empty()) {
            return out;
        }

        auto beg = src.begin();
        out = *(beg++);

        for (; beg != src.end(); beg++) {
            out += sep + *beg;
        }

        return std::forward<std::string>(out);
    }

    std::vector<std::string> split_string(
        const std::string &src, 
        const std::string &sep) {
        std::regex regx(sep);
        std::vector<std::string> result;
        std::sregex_token_iterator iter(src.begin(), src.end(), regx, -1);
        while (iter != std::sregex_token_iterator()) {
            result.push_back((iter++)->str());
        }
        return std::forward<std::vector<std::string>>(result);
    }

}  // namespace pump
