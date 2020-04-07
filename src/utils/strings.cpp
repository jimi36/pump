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

#include "pump/utils/strings.h"

namespace pump {
	namespace utils {

		bool gbk_to_utf8(const std::string &src, std::string &des)
		{
#ifdef WIN32
			std::wstring wstr(MultiByteToWideChar(CP_ACP, 0, src.c_str(), -1, NULL, 0) - 1, wchar_t(0));
			MultiByteToWideChar(CP_ACP, 0, src.c_str(), -1, (wchar_t*)wstr.data(), (int32)wstr.size());

			std::string str(WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)wstr.data(), -1, NULL, 0, NULL, NULL) - 1, char(0));
			WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)wstr.data(), -1, (char*)str.data(), (int32)str.size(), NULL, NULL);

			des.append(str.data(), str.size());
#else
			iconv_t cd = iconv_open("utf-8", "gb2312");
			if (cd == (iconv_t)-1)
				return false;

			size_t inlen = src.size();
			size_t outlen = inlen * 3 + 1;

			des.resize(outlen, 0);

			char *psrc = (char*)src.data();
			char *pdes = (char*)des.data();
			size_t ret = iconv(cd, &psrc, &inlen, &pdes, &outlen);
			iconv_close(cd);
			if (ret != (size_t)-1)
				return false;
			des.reserve(outlen);
#endif
			return true;
		}

		bool utf8_to_gbk(const std::string &src, std::string &des)
		{
#ifdef WIN32
			std::wstring wstr(MultiByteToWideChar(CP_UTF8, 0, src.c_str(), -1, NULL, 0), wchar_t(0));
			MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)src.c_str(), -1, (wchar_t*)wstr.data(), (int32)wstr.size() - 1);

			std::string str(WideCharToMultiByte(CP_ACP, 0, wstr.data(), -1, NULL, 0, NULL, NULL), 0);
			WideCharToMultiByte(CP_ACP, 0, wstr.data(), -1, (char*)str.data(), (int32)str.size() - 1, NULL, NULL);

			des.append(str.data(), str.size() - 1);
#else
			iconv_t cd = iconv_open("gb2312", "utf-8");
			if (cd == (iconv_t)-1)
				return false;

			size_t inlen = src.size();
			size_t outlen = inlen * 3 + 1;

			des.resize(outlen, 0);

			char *psrc = (char*)src.c_str();
			char *pdes = (char*)des.c_str();
			int ret = iconv(cd, &psrc, &inlen, &pdes, &outlen);
			iconv_close(cd);
			if (ret != -1)
				return false;
			des.reserve(outlen);
#endif	
			return true;
		}

		std::string join_strings(
			const std::vector<std::string> &srcs, 
			const std::string &sep
		) {
			std::string ret;

			if (srcs.empty())
				return ret;

			auto beg = srcs.begin();
			ret = *(beg++);

			for (; beg != srcs.end(); beg++)
				ret += sep + *beg;

			return std::move(ret);
		}

		void split_string(
			const std::string &src, 
			const std::string &sep, 
			std::vector<std::string> &ret
		) {
			std::regex regx(sep);
			ret.insert(
				ret.end(), 
				std::sregex_token_iterator(src.begin(), src.end(), regx, -1),
				std::sregex_token_iterator()
			);
		}

	}
}
