#include "pump/codec/base64.h"

namespace pump {
	namespace codec {

		PUMP_STATIC c_block_ptr kBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		/* 'Private' declarations */
		PUMP_INLINE void a3_to_a4(uint8_ptr a4, uint8_ptr a3);
		PUMP_INLINE void a4_to_a3(uint8_ptr a3, uint8_ptr a4);
		PUMP_INLINE uint8 b64_lookup(uint8 c);

		PUMP_INLINE PUMP_STATIC uint32 encoded_length(uint32 length)
		{
			return (length + 2 - ((length + 2) % 3)) / 3 * 4;
		}

		PUMP_INLINE PUMP_STATIC uint32 encoded_length(PUMP_CONST std::string &in)
		{
			return encoded_length((uint32)in.length());
		}

		uint32 base64_encode_length(PUMP_CONST std::string &in)
		{
			return encoded_length((uint32)in.length());
		}

		bool base64_encode(PUMP_CONST std::string &in, std::string &out) 
		{
			int32 i = 0, j = 0;
			int32 enc_len = 0;
			uint8 a3[3];
			uint8 a4[4];

			uint32 input_len = (uint32)in.size();
			std::string::const_iterator input = in.begin();

			if (out.size() < encoded_length(in))
				return false;

			while (input_len--) 
			{
				a3[i++] = *(input++);
				if (i == 3) 
				{
					a3_to_a4(a4, a3);

					for (i = 0; i < 4; i++) {
						out[enc_len++] = kBase64Alphabet[(int32)a4[i]];
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
					out[enc_len++] = kBase64Alphabet[(int32)a4[j]];
				}

				while ((i++ < 3)) 
				{
					out[enc_len++] = '=';
				}
			}

			return (enc_len == (int32)out.size());
		}

		PUMP_STATIC uint32 decoded_length(PUMP_CONST std::string &in)
		{
			uint32 eq_cnt = 0;
			uint32 n = (uint32)in.size();

			for (std::string::const_reverse_iterator it = in.rbegin(); *it == '='; ++it) 
			{
				++eq_cnt;
			}

			return ((6 * n) / 8) - eq_cnt;
		}

		uint32 base64_decode_length(PUMP_CONST std::string &in)
		{
			return decoded_length(in);
		}

		bool base64_decode(PUMP_CONST std::string &in, std::string &out)
		{
			int32 i = 0, j = 0;
			int32 dec_len = 0;
			uint8 a3[3];
			uint8 a4[4];

			uint32 input_len = (uint32)in.size();
			std::string::const_iterator input = in.begin();

			if (out.size() < decoded_length(in))
				return false;

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

			return (dec_len == (int32)out.size());
		}

		PUMP_INLINE void a3_to_a4(uint8_ptr a4, uint8_ptr a3)
		{
			a4[0] = (a3[0] & 0xfc) >> 2;
			a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
			a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
			a4[3] = (a3[2] & 0x3f);
		}

		PUMP_INLINE void a4_to_a3(uint8_ptr a3, uint8_ptr a4)
		{
			a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
			a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
			a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
		}

		PUMP_INLINE uint8 b64_lookup(uint8 c)
		{
			if (c >= 'A' && c <= 'Z') return c - 'A';
			if (c >= 'a' && c <= 'z') return c - 71;
			if (c >= '0' && c <= '9') return c + 4;
			if (c == '+') return 62;
			if (c == '/') return 63;
			return -1;
		}

	}
}
