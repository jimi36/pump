#include "pump/codec/base64.h"

namespace pump {
	namespace codec {

		static c_block_ptr kBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		/* 'Private' declarations */
		inline void a3_to_a4(block_ptr a4, block_ptr a3);
		inline void a4_to_a3(block_ptr a3, block_ptr a4);
		inline block b64_lookup(block c);

		inline static int32 encoded_length(size_t length) 
		{
			return (length + 2 - ((length + 2) % 3)) / 3 * 4;
		}

		inline static int32 encoded_length(const std::string &in) 
		{
			return encoded_length(in.length());
		}

		bool base64_encode(const std::string &in, std::string &out) 
		{
			int32 i = 0, j = 0;
			size_t enc_len = 0;
			block a3[3];
			block a4[4];

			int32 input_len = in.size();
			std::string::const_iterator input = in.begin();

			out.resize(encoded_length(in));

			while (input_len--) 
			{
				a3[i++] = *(input++);
				if (i == 3) 
				{
					a3_to_a4(a4, a3);

					for (i = 0; i < 4; i++) {
						out[enc_len++] = kBase64Alphabet[a4[i]];
					}

					i = 0;
				}
			}

			if (i) 
			{
				for (j = i; j < 3; j++) 
				{
					a3[j] = '\0';
				}

				a3_to_a4(a4, a3);

				for (j = 0; j < i + 1; j++) 
				{
					out[enc_len++] = kBase64Alphabet[a4[j]];
				}

				while ((i++ < 3)) 
				{
					out[enc_len++] = '=';
				}
			}

			return (enc_len == out.size());
		}

		static int32 decoded_length(const std::string &in) 
		{
			int32 eq_cnt = 0;
			int32 n = in.size();

			for (std::string::const_reverse_iterator it = in.rbegin(); *it == '='; ++it) 
			{
				++eq_cnt;
			}

			return ((6 * n) / 8) - eq_cnt;
		}

		bool base64_decode(const std::string &in, std::string &out) 
		{
			int32 i = 0, j = 0;
			size_t dec_len = 0;
			block a3[3];
			block a4[4];

			int32 input_len = in.size();
			std::string::const_iterator input = in.begin();

			out.resize(decoded_length(in));

			while (input_len--) 
			{
				if (*input == '=') 
				{
					break;
				}

				a4[i++] = *(input++);
				if (i == 4) 
				{
					for (i = 0; i < 4; i++) 
					{
						a4[i] = b64_lookup(a4[i]);
					}

					a4_to_a3(a3, a4);

					for (i = 0; i < 3; i++) 
					{
						out[dec_len++] = a3[i];
					}

					i = 0;
				}
			}

			if (i) 
			{
				for (j = i; j < 4; j++) 
				{
					a4[j] = '\0';
				}

				for (j = 0; j < 4; j++) 
				{
					a4[j] = b64_lookup(a4[j]);
				}

				a4_to_a3(a3, a4);

				for (j = 0; j < i - 1; j++) 
				{
					out[dec_len++] = a3[j];
				}
			}

			return (dec_len == out.size());
		}

		inline void a3_to_a4(block_ptr a4, block_ptr a3) {
			a4[0] = (a3[0] & 0xfc) >> 2;
			a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
			a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
			a4[3] = (a3[2] & 0x3f);
		}

		inline void a4_to_a3(block_ptr a3, block_ptr a4) {
			a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
			a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
			a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
		}

		inline block b64_lookup(block c) {
			if (c >= 'A' && c <= 'Z') return c - 'A';
			if (c >= 'a' && c <= 'z') return c - 71;
			if (c >= '0' && c <= '9') return c + 4;
			if (c == '+') return 62;
			if (c == '/') return 63;
			return -1;
		}

	}
}