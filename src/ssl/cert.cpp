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

#include "pump/debug.h"
#include "pump/config.h"
#include "pump/ssl/cert.h"

#if defined(PUMP_HAVE_OPENSSL)
extern "C" {
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
}
#endif

#if defined(PUMP_HAVE_GNUTLS)
extern "C" {
#include <gnutls/gnutls.h>
}
#endif

namespace pump {
namespace ssl {

    x509_certificate generate_x509_certificate(signature_scheme scheme) {
        x509_certificate cert = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        switch (scheme) {
        case TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256:
        case TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384:
        case TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512:
            {
                EC_KEY *eckey = nullptr;
                const EVP_MD *md = nullptr;
                if (scheme == TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256) {
                    md = EVP_sha256();
                    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                } else if (scheme == TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384) {
                    md = EVP_sha384();
                    eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
                } else if (scheme == TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512) {
                    md = EVP_sha512();
                    eckey = EC_KEY_new_by_curve_name(NID_secp521r1);
                }
                PUMP_ASSERT(eckey != nullptr);
                EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
                PUMP_DEBUG_EQUAL_CHECK(EC_KEY_generate_key(eckey), 1);

                EVP_PKEY* pkey = EVP_PKEY_new();
                PUMP_DEBUG_EQUAL_CHECK(EVP_PKEY_assign_EC_KEY(pkey, eckey), 1);
                
                X509 *x509 = X509_new();
                PUMP_ASSERT(x509 != nullptr);
                X509_set_version(x509, 2);
                PUMP_DEBUG_EQUAL_CHECK(ASN1_INTEGER_set(X509_get_serialNumber(x509), 3), 1);
                PUMP_DEBUG_NOEQUAL_CHECK(X509_gmtime_adj(X509_get_notBefore(x509), 0), nullptr);
                PUMP_DEBUG_NOEQUAL_CHECK(X509_gmtime_adj(X509_get_notAfter(x509), 365L * 86400), nullptr);
                PUMP_DEBUG_EQUAL_CHECK(X509_set_pubkey(x509, pkey), 1);

                X509_NAME *name = X509_get_subject_name(x509);
                X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (uint8_t*)"CA", -1, -1, 0);
                X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (uint8_t*)"MyCompany Inc.", -1, -1, 0);
                X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (uint8_t*)"localhost", -1, -1, 0);
                X509_set_issuer_name(x509, name);

                PUMP_DEBUG_NOEQUAL_CHECK(X509_sign(x509, pkey, md), 0);
                EVP_PKEY_free(pkey);

                cert = x509;
            }
            break;
        default:
            break;
        }
#endif
        return cert;
    }

    std::string to_x509_certificate_pem(x509_certificate cert) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        BIO *bio = BIO_new(BIO_s_mem());
        PUMP_ASSERT(bio);
        PEM_write_bio_X509(bio, (X509*)cert);
        BUF_MEM *buf = nullptr;
        BIO_get_mem_ptr(bio, &buf);
        out.assign(buf->data, buf->length);
        BIO_free(bio);
#endif
        return std::forward<std::string>(out);
    }

    std::string to_x509_certificate_raw(x509_certificate cert) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        out.resize(i2d_X509((X509*)cert, nullptr));
        uint8_t *buffer = (uint8_t*)out.data();
        i2d_X509((X509*)cert, &buffer);
#endif
        return std::forward<std::string>(out);
    }

    x509_certificate load_x509_certificate_by_pem(const std::string &data) {
        return load_x509_certificate_by_pem((const uint8_t*)data.data(), (int32_t)data.size());
    }

    x509_certificate load_x509_certificate_by_pem(const uint8_t *data, int32_t size) {
#if defined(PUMP_HAVE_OPENSSL)
        BIO *bio = BIO_new_mem_buf((c_void_ptr)data, size);
        PUMP_ASSERT(bio);
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        PUMP_ASSERT(cert);
        BIO_free(bio);
        return cert;
#else
        return nullptr;
#endif
    }

    x509_certificate load_x509_certificate_by_raw(const std::string &data) {
        return load_x509_certificate_by_raw((const uint8_t*)data.data(), (int32_t)data.size());
    }

    x509_certificate load_x509_certificate_by_raw(const uint8_t *data, int32_t size) {
#if defined(PUMP_HAVE_OPENSSL)
        return d2i_X509(nullptr, &data, size);
#else
        return nullptr;
#endif
    }

    void free_x509_certificate(x509_certificate cert) {
#if defined(PUMP_HAVE_OPENSSL)
        X509_free((X509*)cert);
#endif
    }

    bool verify_x509_certificates(std::vector<x509_certificate> &certs) {
#if defined(PUMP_HAVE_OPENSSL)
        X509_STORE *store = X509_STORE_new();
        for (int32_t i = 1; i < (int32_t)certs.size(); i++) {
            X509_STORE_add_cert(store, (X509*)certs[i]);
        }

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, (X509*)certs[0], NULL);
        int32_t ret = X509_verify_cert(ctx);
        if (ret != 1) {
            int32_t ec = X509_STORE_CTX_get_error(ctx);
            if (ec == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
                ret = 1;
            }
        }

        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);

        return ret == 1;
#else
        return false;
#endif
    }

    bool has_x509_scts(x509_certificate cert) {
#if defined(PUMP_HAVE_OPENSSL)
        if (X509_get_ext_by_NID((const X509*)cert, NID_ct_precert_scts, -1) >= 0) {
            return true;
        }
#endif
        return false;
    }

    bool get_x509_scts(x509_certificate cert, std::vector<std::string> &scts) {
#if defined(PUMP_HAVE_OPENSSL)
        int32_t ext_count = X509_get_ext_count((X509*)cert);
        for (int32_t i = 0; i < ext_count; i++) {
            X509_EXTENSION *ext = X509_get_ext((X509*)cert, i);
            if (ext == nullptr) {
                continue;
            }
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
            if (obj == nullptr) {
                continue;
            }
            int32_t nid = OBJ_obj2nid(obj);
            /*
            if (nid == NID_undef) {
                char extname[128] = {0};
                OBJ_obj2txt(extname, sizeof(extname), (const ASN1_OBJECT *) obj, 1);
                PUMP_DEBUG_LOG("extension name is %s", extname);
            } else {
                const char *c_ext_name = OBJ_nid2ln(nid);
                PUMP_DEBUG_LOG("extension name is %s", c_ext_name);
            }
            */
            if (nid != NID_ct_precert_scts) {
                continue;
            }
            BIO *bio = BIO_new(BIO_s_mem());
            if(X509V3_EXT_print(bio, ext, 0, 0) == 1){
                BUF_MEM *bptr = NULL;
                BIO_flush(bio);
                BIO_get_mem_ptr(bio, &bptr);
                scts.push_back(bptr->data);
            }
            BIO_free(bio);
        }

        return true;
#else
        return false;
#endif
    }

    signature_scheme get_x509_signature_scheme(x509_certificate cert) {
#if defined(PUMP_HAVE_OPENSSL)
        EVP_PKEY *pkey = X509_get_pubkey((X509*)cert);
        switch (EVP_PKEY_base_id(pkey)) {
        case EVP_PKEY_RSA:
        {
            int32_t pkey_size = EVP_PKEY_size(pkey);
            if (pkey_size == 256) {
                return TLS_SIGN_SCHE_PSSWITHSHA256;
            } else if (pkey_size == 384) {
                return TLS_SIGN_SCHE_PSSWITHSHA384;
            } else if (pkey_size == 512) {
                return TLS_SIGN_SCHE_PSSWITHSHA512;
            }
            break;
        }
        case EVP_PKEY_EC:
        {
            EC_KEY *key = EVP_PKEY_get1_EC_KEY(pkey);
            int32_t curve = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
            if (curve == NID_X9_62_prime256v1) {
                return TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256;
            } else if (curve == NID_secp384r1) {
                return TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384;
            } else if (curve == NID_secp521r1) {
                return TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512;
            }
            break;
        }
        case EVP_PKEY_ED25519:
            return TLS_SIGN_SCHE_ED25519;
        }
#endif
        return TLS_SIGN_SCHE_UNKNOWN;
    }

    static int32_t __get_ssl_hash_id(hash_algorithm algo) {
        PUMP_ASSERT(algo > HASH_UNKNOWN && algo <= HASH_SHA512);
#if defined(PUMP_HAVE_OPENSSL)
        const static int32_t hash_ids[] = {
            -1, 
            NID_sha1,
            NID_sha224, 
            NID_sha256, 
            NID_sha384, 
            NID_sha512
        };
        return hash_ids[algo];
#else
        return -1;
#endif
    }

    bool do_x509_signature(
        x509_certificate cert, 
        signature_algorithm sign_algo, 
        hash_algorithm hash_algo,
        const std::string &msg,
        std::string &sign) {
        bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
        switch (sign_algo) {
        case TLS_SIGN_ALGO_PKCS1V15:
        {
            uint32_t sign_len = 0;
            EVP_PKEY *pubkey = X509_get_pubkey((X509*)cert);
            RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
            ret = RSA_sign(
                    __get_ssl_hash_id(hash_algo),
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    NULL, 
                    &sign_len,
                    rsa) == 1;
            if (ret) {
                sign.resize(sign_len);
                RSA_sign(
                    __get_ssl_hash_id(hash_algo),
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    (uint8_t*)sign.data(), 
                    &sign_len,
                    rsa);
            }
            EVP_PKEY_free(pubkey);
            RSA_free(rsa);
            break;
        }
        case TLS_SIGN_ALGO_RSAPSS:
            break;
        case TLS_SIGN_ALGO_ECDSA:
        {
            uint32_t sign_len = 0;
            EVP_PKEY *pubkey = X509_get_pubkey((X509*)cert);
            EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pubkey);
            ret = ECDSA_sign(
                    0, 
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    NULL, 
                    &sign_len, 
                    ec_key) == 1;
            if (ret) {
                sign.resize(sign_len);
                ECDSA_sign(
                    0, 
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    (uint8_t*)sign.data(), 
                    &sign_len, 
                    ec_key);
            }
            EVP_PKEY_free(pubkey);
            EC_KEY_free(ec_key);
            break;
        }
        case TLS_SIGN_ALGO_ED25519:
        {
            size_t sign_len = 256;
            sign.resize(sign_len);
            EVP_PKEY_CTX *pctx = nullptr;
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_PKEY *pkey = X509_get_pubkey((X509*)cert);
            EVP_DigestSignInit(ctx, &pctx, nullptr, nullptr, pkey);
            ret = EVP_DigestSign(
                    ctx, 
                    (uint8_t*)sign.data(), 
                    &sign_len, 
                    (const uint8_t*)msg.data(), 
                    msg.size()) == 1;
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            break;
        }
        default:
            break;
        }
#endif
        return ret;
    }

    bool verify_x509_signature(
        x509_certificate cert, 
        signature_algorithm sign_algo, 
        hash_algorithm hash_algo,        
        const std::string &msg, 
        const std::string &sign) {
        bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
        switch (sign_algo) {
        case TLS_SIGN_ALGO_PKCS1V15:
        {
            EVP_PKEY *pubkey = X509_get_pubkey((X509*)cert);
            RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
            ret = RSA_verify(
                    __get_ssl_hash_id(hash_algo), 
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    (const uint8_t*)sign.data(), 
                    (int32_t)sign.size(), 
                    rsa) == 1;
            EVP_PKEY_free(pubkey);
            RSA_free(rsa);
            break;
        }
        case TLS_SIGN_ALGO_RSAPSS:
            break;
        case TLS_SIGN_ALGO_ECDSA:
        {
            EVP_PKEY *pubkey = X509_get_pubkey((X509*)cert);
            EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pubkey);
            ret = ECDSA_verify(
                    0, 
                    (const uint8_t*)msg.data(), 
                    (int32_t)msg.size(), 
                    (const uint8_t*)sign.data(), 
                    (int32_t)sign.size(), 
                    ec_key) == 1;
            EVP_PKEY_free(pubkey);
            EC_KEY_free(ec_key);
            break;
        }
        case TLS_SIGN_ALGO_ED25519:
        {
            EVP_PKEY_CTX *pctx = nullptr;
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_PKEY *pkey = X509_get_pubkey((X509*)cert);
            EVP_DigestSignInit(ctx, &pctx, nullptr, nullptr, pkey);
            ret = EVP_DigestVerify(
                    ctx, 
                    (uint8_t*)sign.data(), 
                    sign.size(), 
                    (const uint8_t*)msg.data(), 
                    msg.size()) == 1;
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            break;
        }
        default:
            break;
        }
#endif
        return ret;
    }

}  // namespace ssl
}  // namespace pump