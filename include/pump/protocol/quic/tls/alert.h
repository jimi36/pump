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
 
#ifndef pump_protocol_quic_tls_alert_h
#define pump_protocol_quic_tls_alert_h

#include "pump/types.h"

namespace pump {
namespace protocol {
namespace quic {
namespace tls {

    typedef uint64_t tls_alert_code;
    #define DEFINE_TLS_ALERT(alert, code, desc) \
        const static tls_alert_code alert = code;
        // const static char* alert##_desc = desc;

    // https://tools.ietf.org/html/rfc8446#section-6
    typedef uint64_t alert_code;
    DEFINE_TLS_ALERT(ALERT_NONE,                            -1, "")
    DEFINE_TLS_ALERT(ALERT_CLOSE_NOTIFY,                    0,  "close notify")
    DEFINE_TLS_ALERT(ALERT_UNEXPECTED_MESSGAE,              10, "unexpected message")
    DEFINE_TLS_ALERT(ALERT_BAD_RECORD_MAC,                  20, "bad record MAC")
    DEFINE_TLS_ALERT(ALERT_DEVRYPTION_FAILED,               21, "decryption failed")
    DEFINE_TLS_ALERT(ALERT_RECORD_OVER_FLOW,                22, "record overflow")
    DEFINE_TLS_ALERT(ALERT_DEVOMPRESSION_FAILURE,           30, "record overflow")
    DEFINE_TLS_ALERT(ALERT_HANDSHAKE_FAILURE,               40, "handshake failure")
    DEFINE_TLS_ALERT(ALERT_BAD_CERTIFICATE,                 42, "bad certificate")
    DEFINE_TLS_ALERT(ALERT_UNSUPPORTED_CERTIFICATE,         43, "unsupported certificate")
    DEFINE_TLS_ALERT(ALERT_CERTIFICATE_REVOKED,             44, "revoked certificate")
    DEFINE_TLS_ALERT(ALERT_CERTIFICATE_EXPIRED,             45, "expired certificate")
    DEFINE_TLS_ALERT(ALERT_CERTIFICATE_UNKNOWN,             46, "unknown certificate")
    DEFINE_TLS_ALERT(ALERT_ILLEGAL_PARAMETER,               47, "illegal parameter")
    DEFINE_TLS_ALERT(ALERT_UNKNOWN_CA,                      48, "unknown certificate authority")
    DEFINE_TLS_ALERT(ALERT_ACCESS_DENIED,                   49, "access denied")
    DEFINE_TLS_ALERT(ALERT_DECODE_ERROR,                    50, "error decoding message")
    DEFINE_TLS_ALERT(ALERT_DECRYPT_ERROR,                   51, "error decrypting message")
    DEFINE_TLS_ALERT(ALERT_EXPORT_RESTRICTION,              60, "export restriction")
    DEFINE_TLS_ALERT(ALERT_PROTOCOL_VERSION,                70, "protocol version not supported")
    DEFINE_TLS_ALERT(ALERT_INSUFFICIENT_SECURITY,           71, "insufficient security level")
    DEFINE_TLS_ALERT(ALERT_INTERNAL_ERROR,                  80, "internal error")
    DEFINE_TLS_ALERT(ALERT_INAPPROPRIATE_FALLBACK,          86, "inappropriate fallback")
    DEFINE_TLS_ALERT(ALERT_USER_CANCELED,                   90, "user canceled")
    DEFINE_TLS_ALERT(ALERT_NO_RENEGOTIATION,                100, "no renegotiation")
    DEFINE_TLS_ALERT(ALERT_MISSING_EXTENSION,               109, "missing extension")
    DEFINE_TLS_ALERT(ALERT_UNSUPPORTED_EXTENSION,           110, "unsupported extension")
    DEFINE_TLS_ALERT(ALERT_CERTIFICATE_UNOBTAINABLE,        111, "certificate unobtainable")
    DEFINE_TLS_ALERT(ALERT_UNRECOGNIZED_NAME,               112, "unrecognized name")
    DEFINE_TLS_ALERT(ALERT_BAD_CERTIFICATE_STATUS_RESPONSE, 113, "bad certificate status response")
    DEFINE_TLS_ALERT(ALERT_BAD_CERTIFICATE_HASH_VALUE,      114, "bad certificate hash value")
    DEFINE_TLS_ALERT(ALERT_UNKNOWN_PSK_IDENTITY,            115, "unknown PSK identity")
    DEFINE_TLS_ALERT(ALERT_CERTIFICATE_REQUIRED,            116, "certificate required")
    DEFINE_TLS_ALERT(ALERT_NO_APPLICATION_PROTOCOL,         120, "no application protocol")

    #define TLS_ALERT_DESC(x) x##_desc

    #undef DEFINE_TLS_ALERT

}
}
}
}

#endif