#include "pump/codec/base64.h"

namespace pump {
namespace codec {

    static const block_t *kBase64Alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /* 'Private' declarations */
    PUMP_INLINE void a3_to_a4(uint8_t *a4, uint8_t *a3);
    PUMP_INLINE void a4_to_a3(uint8_t *a3, uint8_t *a4);
    PUMP_INLINE uint8_t b64_lookup(uint8_t c);

    PUMP_INLINE static uint32_t encoded_length(uint32_t length) {
        return (length + 2 - ((length + 2) % 3)) / 3 * 4;
    }

    PUMP_INLINE static uint32_t encoded_length(const std::string &in) {
        return encoded_length((uint32_t)in.length());
    }

    uint32_t base64_encode_length(const std::string &in) {
        return encoded_length((uint32_t)in.length());
    }

    std::string base64_encode(const std::string &in) {
        int32_t i = 0, j = 0;
        int32_t enc_len = 0;
        uint8_t a3[3];
        uint8_t a4[4];

        uint32_t input_len = (uint32_t)in.size();
        std::string::const_iterator input = in.begin();

        std::string out(encoded_length(in), 0);

        while (input_len--) {
            a3[i++] = *(input++);
            if (i == 3) {
                a3_to_a4(a4, a3);

                for (i = 0; i < 4; i++) {
                    out[enc_len++] = kBase64Alphabet[(int32_t)a4[i]];
                }

                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 3; j++) {
                a3[j] = '\0';
            }

            a3_to_a4(a4, a3);

            for (j = 0; j < i + 1; j++) {
                out[enc_len++] = kBase64Alphabet[(int32_t)a4[j]];
            }

            while ((i++ < 3)) {
                out[enc_len++] = '=';
            }
        }

        return out;
    }

    PUMP_INLINE static uint32_t decoded_length(const std::string &in) {
        uint32_t eq_cnt = 0;
        uint32_t n = (uint32_t)in.size();

        for (std::string::const_reverse_iterator it = in.rbegin(); *it == '='; ++it) {
            ++eq_cnt;
        }

        return ((6 * n) / 8) - eq_cnt;
    }

    uint32_t base64_decode_length(const std::string &in) {
        return decoded_length(in);
    }

    std::string base64_decode(const std::string &in) {
        int32_t i = 0, j = 0;
        int32_t dec_len = 0;
        uint8_t a3[3];
        uint8_t a4[4];

        uint32_t input_len = (uint32_t)in.size();
        std::string::const_iterator input = in.begin();

        std::string out(decoded_length(in), 0);

        while (input_len--) {
            if (*input == '=') {
                break;
            }

            a4[i++] = *(input++);
            if (i == 4) {
                for (i = 0; i < 4; i++) {
                    a4[i] = b64_lookup(a4[i]);
                }

                a4_to_a3(a3, a4);

                for (i = 0; i < 3; i++) {
                    out[dec_len++] = a3[i];
                }

                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++) {
                a4[j] = '\0';
            }

            for (j = 0; j < 4; j++) {
                a4[j] = b64_lookup(a4[j]);
            }

            a4_to_a3(a3, a4);

            for (j = 0; j < i - 1; j++) {
                out[dec_len++] = a3[j];
            }
        }

        return out;
    }

    PUMP_INLINE void a3_to_a4(uint8_t *a4, uint8_t *a3) {
        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
        a4[3] = (a3[2] & 0x3f);
    }

    PUMP_INLINE void a4_to_a3(uint8_t *a3, uint8_t *a4) {
        a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
        a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
        a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
    }

    PUMP_INLINE uint8_t b64_lookup(uint8_t c) {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 71;
        if (c >= '0' && c <= '9')
            return c + 4;
        if (c == '+')
            return 62;
        if (c == '/')
            return 63;
        return -1;
    }

}  // namespace codec
}  // namespace pump
