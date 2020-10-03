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

#if defined(OS_LINUX)
#include <iconv.h>
#endif

namespace pump {

uint8 decnum_to_hexchar(uint8 n) {
    if (n >= 0 && n <= 9) {
        return uint8('0') + n;
    } else if (n >= 10 && n <= 15) {
        return uint8('A') + n - 10;
    }
    return 0;
}

uint8 hexchar_to_decnum(uint8 c) {
    if (c >= '0' && c <= '9') {
        return uint8(c - '0');
    } else if (c >= 'a' && c <= 'f') {
        return (uint8(c - 'a') + 10);
    } else if (c >= 'A' && c <= 'F') {
        return (uint8(c - 'A') + 10);
    }
    return 0;
}

std::string gbk_to_utf8(const std::string &in) {
    std::string out;
#if defined(OS_WINDOWS)
    std::wstring wstr(MultiByteToWideChar(CP_ACP, 0, in.c_str(), -1, NULL, 0) - 1,
                      wchar_t(0));
    MultiByteToWideChar(
        CP_ACP, 0, in.c_str(), -1, (wchar_t *)wstr.data(), (int32)wstr.size());

    std::string str(
        WideCharToMultiByte(CP_UTF8, 0, (wchar_t *)wstr.data(), -1, NULL, 0, NULL, NULL) -
            1,
        char(0));
    WideCharToMultiByte(CP_UTF8,
                        0,
                        (wchar_t *)wstr.data(),
                        -1,
                        (char *)str.data(),
                        (int32)str.size(),
                        NULL,
                        NULL);

    out.append(str.data(), str.size());
#else
    iconv_t cd = iconv_open("utf-8", "gb2312");
    if (cd != (iconv_t)-1) {
        size_t inlen = in.size();
        block_ptr psrc = (block_ptr)in.data();

        size_t outlen = inlen * 3 + 1;
        out.resize(outlen, 0);
        block_ptr pdes = (block_ptr)out.data();

        iconv(cd, &psrc, &inlen, &pdes, &outlen);
        out.reserve(outlen);

        iconv_close(cd);
    }

#endif
    return out;
}

std::string utf8_to_gbk(const std::string &in) {
    std::string out;
#if defined(OS_WINDOWS)
    std::wstring wstr(MultiByteToWideChar(CP_UTF8, 0, in.c_str(), -1, NULL, 0),
                      wchar_t(0));
    MultiByteToWideChar(CP_UTF8,
                        0,
                        (LPCSTR)in.c_str(),
                        -1,
                        (wchar_t *)wstr.data(),
                        (int32)wstr.size() - 1);

    std::string str(WideCharToMultiByte(CP_ACP, 0, wstr.data(), -1, NULL, 0, NULL, NULL),
                    0);
    WideCharToMultiByte(CP_ACP,
                        0,
                        wstr.data(),
                        -1,
                        (char *)str.data(),
                        (int32)str.size() - 1,
                        NULL,
                        NULL);

    out.append(str.data(), str.size() - 1);
#else
    iconv_t cd = iconv_open("gb2312", "utf-8");
    if (cd != (iconv_t)-1) {
        size_t inlen = in.size();
        block_ptr psrc = (block_ptr)in.c_str();

        size_t outlen = inlen * 3 + 1;
        out.resize(outlen, 0);
        block_ptr pdes = (block_ptr)out.c_str();

        iconv(cd, &psrc, &inlen, &pdes, &outlen);
        out.reserve(outlen);

        iconv_close(cd);
    }
#endif
    return out;
}

std::string join_strings(const std::vector<std::string> &src, const std::string &sep) {
    std::string out;

    if (src.empty()) {
        return out;
    }

    auto beg = src.begin();
    out = *(beg++);

    for (; beg != src.end(); beg++) {
        out += sep + *beg;
    }

    return out;
}

std::vector<std::string> split_string(const std::string &src, const std::string &sep) {
    std::vector<std::string> out;

    std::regex regx(sep);
    out.insert(out.end(),
               std::sregex_token_iterator(src.begin(), src.end(), regx, -1),
               std::sregex_token_iterator());

    return out;
}

}  // namespace pump
