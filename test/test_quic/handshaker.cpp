#include "handshaker.h"

#include <pump/service.h>
#include <pump/protocol/quic/tls/client.h>
#include <pump/protocol/quic/tls/server.h>

using namespace pump;
using namespace protocol::quic::tls;

client_handshaker *ch = nullptr;
server_handshaker *sh = nullptr;

const char* cert =
"\
-----BEGIN CERTIFICATE-----\n\
MIIESjCCArKgAwIBAgIBBzANBgkqhkiG9w0BAQsFADA3MQwwCgYDVQQLEwN6aHQx\
DDAKBgNVBAoTA3podDEMMAoGA1UECBMDemh0MQswCQYDVQQGEwJDTjAeFw0yMDAz\
MTcwNzE4MTFaFw0yNzExMTYwNzE4MzFaMDcxDDAKBgNVBAsTA3podDEMMAoGA1UE\
ChMDemh0MQwwCgYDVQQIEwN6aHQxCzAJBgNVBAYTAkNOMIIBojANBgkqhkiG9w0B\
AQEFAAOCAY8AMIIBigKCAYEArPK8IBbrmbnJRHUsQCipKxXFmqfvHSSj5yYoPBxl\
UkGoc3Mtz0ftUxZnSotREkbwYw1zJwSC4pET8xZvNSn/b1J2yhZe0Jdwj9SSo7Sn\
V12wdxQTD13y6YNv1zegXUlABbnrFLgUcON8nV3BeFRI7X1x8EiCw88FDajS+2r4\
YYVJnODvkPQtq+v/GblrIknlPKmzwFulh8ENoz18nTu3CS8c5yOXAeBwf0+4N0Xy\
aJOqL9DapMWXKU58eH0+wH013HfgrqEP4FUZGlXuBJIdAYNcUn1ULs+d1yvBVqjZ\
CUpglzUwkKLJzuSOF8sLbVU/mhYsaIZtpE3OcMVmDu/vsMJitdszlXo14CeSlJhZ\
J/pNRfDZj1YLkSkPbU8lcxALrwg3f6sYmuN4nrp+J94a3qyGoimLIkVQmzAZYc90\
zWURqcATodPsjSkPqDNFGwIxq7/a2/+hsMMa+267gFfZaitc42yGwcgER5Wq7o9n\
0PrKVBx39vvQ15OzpJ6ANrTLAgMBAAGjYTBfMAwGA1UdEwEB/wQCMAAwDwYDVR0P\
AQH/BAUDAwewADAdBgNVHQ4EFgQUogzhOqJSCSzNvlO14S5XWc4l+BEwHwYDVR0j\
BBgwFoAUkJ0SqbO/hFKzH1srEP9u623g8m4wDQYJKoZIhvcNAQELBQADggGBACJH\
KFDWeAZsSIErgD/PlVuRUmlS2c68PImBtiqlk2HYvDL2XuiHn+JNNa+KbWzWM3JI\
nA+1/VDXHw9iDxmb/72f6DXynPaN0wJZJ2/f1aihPiwOkGIuzOlt5yoTzKkG9CP9\
NOLq3ZhwFgqz3r3l1NU5Ex4/0ZKbYOJ7c4qT0rnTIZWIn7A6BT8DsJVcPaBQQ056\
Pamk3eZvftuRnJbEESImIfhA9TuiqNZ0XPANDHKlAdObKgYYU2Kmm4FyjtvWK8Om\
vGauaUhwG9i9k8XOAuMAATA0GN9aaeGY/WM6wCpGl4BCRYpLHWUhjibUVv9+PDZ9\
C11K2ISTduPrm6ekF4CkbUvkJ7GWISonBzT4t0AY1OB5K4U8z+ZbTOc9UAFVhdHR\
bb07Ta+RRyRqMnF4cy6VyabNXfDCh/RDtdnb5IERZTMCI/Juzocn489IHaHDtH5I\
6zh/dXDkuZYLqnuVt3CRksluuYF6N2lzS5WDXutpkO83U6tGAouOr8VDF32pEg==\n\
-----END CERTIFICATE-----\
";

const char* key =
"\
-----BEGIN RSA PRIVATE KEY-----\n\
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\n\
-----END RSA PRIVATE KEY-----\
";

void client_send_callback(const std::string &data) {
    handshake_message *msg = new_handshake_message((message_type)data[0]);
    int32_t ret = unpack_handshake_message((const uint8_t*)data.data(), (int32_t)data.size(), msg);
    if (ret != (int32_t)data.size()) {
        printf("client_send_callback unpack_handshake_message failed %d\n", ret);
    } else {
        if (!sh->handshake(msg)) {
            printf("client_send_callback server handshake failed\n");
        }
    }
    delete_handshake_message(msg);
}

void server_send_callback(const std::string &data) {
    handshake_message *msg = new_handshake_message((message_type)data[0]);
    int32_t ret = unpack_handshake_message((const uint8_t*)data.data(), (int32_t)data.size(), msg);
    if (ret != (int32_t)data.size()) {
        printf("server_send_callback unpack_handshake_message failed %d\n", ret);
        return;
    } else {
        if (!ch->handshake(msg)) {
            printf("server_send_callback client handshake failed\n");
        }
    }
    delete_handshake_message(msg);
}

void test_handshaker() {
    service *sv = new pump::service;
    sv->start();

    sh = new server_handshaker();
    sh->set_send_callback(pump_bind(server_send_callback, _1));

    config scfg;
    //scfg.cert = cert;
    scfg.alpn = "test";
    scfg.server_name = "local";
    sh->handshake(&scfg);

    ch = new client_handshaker();
    ch->set_send_callback(pump_bind(client_send_callback, _1));

    config ccfg;
    ccfg.alpn = "test";
    ccfg.server_name = "local";
    ch->handshake(&ccfg);

    sv->wait_stopped();
}