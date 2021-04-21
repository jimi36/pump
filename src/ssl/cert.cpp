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
#include <openssl/err.h>
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

    struct x509_certificate {
        x509_certificate()
      : key(nullptr),
        cert(nullptr) {
        }
#if defined(PUMP_HAVE_OPENSSL)
        EVP_PKEY *key;
        X509 *cert;
#endif
    };

    x509_certificate* generate_x509_certificate(signature_scheme scheme) {
        x509_certificate *xcert = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        switch (scheme) {
        case TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256:
        case TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384:
        case TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512:
            {
                EC_KEY *eckey = nullptr;
                const EVP_MD *(*new_md_fn)() = nullptr;
                if (scheme == TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256) {
                    new_md_fn = EVP_sha256;
                    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                } else if (scheme == TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384) {
                    new_md_fn = EVP_sha384;
                    eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
                } else if (scheme == TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512) {
                    new_md_fn = EVP_sha512;
                    eckey = EC_KEY_new_by_curve_name(NID_secp521r1);
                } else {
                    PUMP_DEBUG_LOG("generate_x509_certificate: unkonwn signature scheme %d", scheme);
                    break;
                }
                if (eckey == nullptr) {
                    break;
                }
                EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
                PUMP_DEBUG_COND_CHECK(EC_KEY_generate_key(eckey), ==, 1);

                EVP_PKEY *pkey = EVP_PKEY_new();
                if (pkey == nullptr) {
                    PUMP_DEBUG_LOG("generate_x509_certificate: EVP_PKEY_new failed");
                    EC_KEY_free(eckey);
                    break;
                }
                PUMP_DEBUG_COND_CHECK(EVP_PKEY_assign_EC_KEY(pkey, eckey), ==, 1);
                
                X509 *cert = X509_new();
                if (cert == nullptr) {
                    EVP_PKEY_free(pkey);
                    break;
                }
                PUMP_DEBUG_COND_CHECK(X509_set_version(cert, 3), ==, 1);
                PUMP_DEBUG_COND_CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert), 3), ==, 1);
                PUMP_DEBUG_COND_CHECK(X509_gmtime_adj(X509_get_notBefore(cert), 0), !=, nullptr);
                PUMP_DEBUG_COND_CHECK(X509_gmtime_adj(X509_get_notAfter(cert), 365L * 86400), !=, nullptr);
                PUMP_DEBUG_COND_CHECK(X509_set_pubkey(cert, pkey), ==, 1);

                X509_NAME *name = X509_get_subject_name(cert);
                if (name == nullptr) {
                    EVP_PKEY_free(pkey);
                    X509_free(cert);
                    break;
                }
                PUMP_DEBUG_COND_CHECK(X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (uint8_t*)"CA", -1, -1, 0), ==, 1);
                PUMP_DEBUG_COND_CHECK(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (uint8_t*)"MyCompany Inc.", -1, -1, 0), == , 1);
                PUMP_DEBUG_COND_CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (uint8_t*)"localhost", -1, -1, 0), ==, 1);
                PUMP_DEBUG_COND_CHECK(X509_set_issuer_name(cert, name), ==, 1);
                
                PUMP_DEBUG_COND_CHECK(X509_sign(cert, pkey, new_md_fn()), >, 0);

                if ((xcert = object_create<x509_certificate>()) == nullptr) {
                    EVP_PKEY_free(pkey);
                    X509_free(cert);
                } else {
                    xcert->key = pkey;
                    xcert->cert = cert;
                }
                break;
            }
        default:
            break;
        }
#endif
        return xcert;
    }

    std::string to_x509_certificate_pem(x509_certificate *xcert) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        do {
            BIO *bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                break;
            }
            PUMP_DEBUG_COND_CHECK(PEM_write_bio_X509(bio, xcert->cert), ==, 1);

            BUF_MEM *buf = nullptr;
            BIO_get_mem_ptr(bio, &buf);
            if (buf == nullptr) {
                BIO_free(bio);
                break;
            }
            out.assign(buf->data, buf->length);

            BIO_free(bio);
        } while(false);
#endif
        return std::forward<std::string>(out);
    }

    std::string to_x509_certificate_raw(x509_certificate *xcert) {
        std::string out;
#if defined(PUMP_HAVE_OPENSSL)
        int32_t size = i2d_X509(xcert->cert, nullptr);
        if (size > 0) {
            out.resize(size);
            uint8_t *buffer = (uint8_t*)out.data();
            PUMP_DEBUG_COND_CHECK(i2d_X509(xcert->cert, &buffer), ==, size);
        }
#endif
        return std::forward<std::string>(out);
    }

    x509_certificate* load_x509_certificate_by_pem(
        const std::string &cert, 
        const std::string &key) {
        return load_x509_certificate_by_pem(
            cert.data(), 
            (int32_t)cert.size(),
            key.data(), 
            (int32_t)key.size());
    }

    x509_certificate* load_x509_certificate_by_pem(
        const block_t *cert, 
        int32_t cert_size,
        const block_t *key, 
        int32_t key_size) {
        x509_certificate *xcert = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        xcert = object_create<x509_certificate>();
        if (xcert == nullptr) {
            return nullptr;
        }

        BIO *bio = BIO_new_mem_buf(cert, cert_size);
        if (bio == nullptr) {
            object_delete(xcert);
            return nullptr;
        }
        xcert->cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (xcert->cert == nullptr) {
            object_delete(xcert);
            return nullptr;
        }

        if (key != nullptr && key_size > 0) {
            bio = BIO_new_mem_buf(key, key_size);
            if (bio == nullptr) {
                X509_free(xcert->cert);
                object_delete(xcert);
                return nullptr;
            }
            xcert->key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            if (xcert->key == nullptr) {
                X509_free(xcert->cert);
                object_delete(xcert);
                return nullptr;
            }
        }
#endif
        return xcert;
    }

    x509_certificate* load_x509_certificate_by_raw(
        const std::string &cert,
        const std::string &key) {
        return load_x509_certificate_by_raw(
            cert.data(), 
            (int32_t)cert.size(),
            key.data(),
            (int32_t)key.size());
    }

    x509_certificate* load_x509_certificate_by_raw(
        const block_t *cert, 
        int32_t cert_size,
        const block_t *key, 
        int32_t key_size) {
        x509_certificate *xcert = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        xcert = object_create<x509_certificate>();
        if (xcert == nullptr) {
            return nullptr;
        }

        const uint8_t *p_cert = (const uint8_t*)cert;
        xcert->cert = d2i_X509(nullptr, &p_cert, cert_size);
        if (xcert->cert == nullptr) {
            object_delete(xcert);
            return nullptr;
        } else {
            if (key != nullptr && key_size > 0) {
                const uint8_t *p_key = (const uint8_t*)key;
                xcert->key = d2i_AutoPrivateKey(nullptr, &p_key, key_size);
                if (xcert->key == nullptr) {
                    X509_free(xcert->cert);
                    object_delete(xcert);
                    return nullptr;
                }
            }
        }
#endif
        return xcert;
    }

    void free_x509_certificate(x509_certificate *xcert) {
        if (xcert == nullptr) {
            return;
        }
        if (xcert->cert) {
#if defined(PUMP_HAVE_OPENSSL)
            X509_free(xcert->cert);
#endif
        }
        if (xcert->key) {
#if defined(PUMP_HAVE_OPENSSL)
            EVP_PKEY_free(xcert->key);
#endif
        }
    }

    bool verify_x509_certificates(std::vector<x509_certificate*> &xcerts) {
#if defined(PUMP_HAVE_OPENSSL)
        X509_STORE *store = X509_STORE_new();
        for (int32_t i = 1; i < (int32_t)xcerts.size(); i++) {
            PUMP_DEBUG_COND_CHECK(X509_STORE_add_cert(store, xcerts[i]->cert), ==, 1);
        }

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        PUMP_DEBUG_COND_CHECK(X509_STORE_CTX_init(ctx, store, xcerts[0]->cert, nullptr), ==, 1);
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

    bool has_x509_scts(x509_certificate *xcert) {
#if defined(PUMP_HAVE_OPENSSL)
       return X509_get_ext_by_NID(xcert->cert, NID_ct_precert_scts, -1) >= 0;
#else
        return false;
#endif
    }

    bool get_x509_scts(
        x509_certificate *xcert, 
        std::vector<std::string> &scts) {
#if defined(PUMP_HAVE_OPENSSL)
        int32_t ext_count = X509_get_ext_count(xcert->cert);
        for (int32_t i = 0; i < ext_count; i++) {
            X509_EXTENSION *ext = X509_get_ext(xcert->cert, i);
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
                BUF_MEM *bptr = nullptr;
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

    signature_scheme get_x509_signature_scheme(x509_certificate *xcert) {
        signature_scheme scheme = TLS_SIGN_SCHE_UNKNOWN;
#if defined(PUMP_HAVE_OPENSSL)
        EVP_PKEY *pkey = X509_get0_pubkey(xcert->cert);
        switch (EVP_PKEY_base_id(pkey)) {
        case EVP_PKEY_RSA:
        {
            int32_t pkey_size = EVP_PKEY_size(pkey);
            if (pkey_size == 256) {
                scheme = TLS_SIGN_SCHE_PSSWITHSHA256;
            } else if (pkey_size == 384) {
                scheme = TLS_SIGN_SCHE_PSSWITHSHA384;
            } else if (pkey_size == 512) {
                scheme = TLS_SIGN_SCHE_PSSWITHSHA512;
            }
            break;
        }
        case EVP_PKEY_EC:
        {
            EC_KEY *key = EVP_PKEY_get0_EC_KEY(pkey);
            int32_t curve = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
            if (curve == NID_X9_62_prime256v1) {
                scheme = TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256;
            } else if (curve == NID_secp384r1) {
                scheme = TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384;
            } else if (curve == NID_secp521r1) {
                scheme = TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512;
            }
            break;
        }
        case EVP_PKEY_ED25519:
            scheme = TLS_SIGN_SCHE_ED25519;
        }
#endif
        return scheme;
    }

    bool do_x509_signature(
        x509_certificate *xcert, 
        signature_algorithm sign_algo, 
        hash_algorithm hash_algo,
        const std::string &msg,
        std::string &sign) {
        bool ret = false;
        size_t sign_len = 0;
#if defined(PUMP_HAVE_OPENSSL)
        PUMP_ASSERT(xcert->key != nullptr);
        if (xcert->key == nullptr) {
            return false;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(xcert->key, nullptr);
        if (ctx == nullptr) {
            return false;
        }

        PUMP_DEBUG_COND_CHECK(EVP_PKEY_sign_init(ctx), ==, 1);

        if (sign_algo == TLS_SIGN_ALGO_PKCS1V15) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING_SIZE), ==, 1);
        } else if (sign_algo == TLS_SIGN_ALGO_RSAPSS) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), ==, 1);
        } else if (sign_algo == TLS_SIGN_ALGO_ECDSA) {
            // Do nothing.
        } else if (sign_algo == TLS_SIGN_ALGO_ED25519) {
            // Do nothing.
        } else {
            goto end;
        }

        if (hash_algo == HASH_SHA1) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1()), ==, 1);
        } else if (hash_algo == HASH_SHA224) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha224()), ==, 1);
        } else if (hash_algo == HASH_SHA256) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()), ==, 1);
        } else if (hash_algo == HASH_SHA384) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384()), ==, 1);
        } else if (hash_algo == HASH_SHA512) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()), ==, 1);
        } else {
            goto end;
        }

        PUMP_DEBUG_COND_CHECK(
            EVP_PKEY_sign(
                ctx, 
                nullptr, 
                &sign_len, 
                (const uint8_t*)msg.data(), 
                msg.size()), 
            ==, 1);
        sign.resize(sign_len);
        PUMP_DEBUG_COND_CHECK(
            EVP_PKEY_sign(
                ctx, 
                (uint8_t*)sign.data(), 
                &sign_len, 
                (const uint8_t*)msg.data(), 
                msg.size()), 
            ==, 1);
        sign.resize(sign_len);

        ret = true;

      end:
        if (ctx != nullptr) {
            EVP_PKEY_CTX_free(ctx);
        }
#endif
        return ret;
    }

    bool verify_x509_signature(
        x509_certificate *xcert, 
        signature_algorithm sign_algo, 
        hash_algorithm hash_algo,        
        const std::string &msg, 
        const std::string &sign) {
        bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
        EVP_PKEY *pkey = X509_get0_pubkey(xcert->cert);
        if (pkey == nullptr) {
            return false;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (ctx == nullptr) {
            EVP_PKEY_free(pkey);
            return false;
        }

        PUMP_DEBUG_COND_CHECK(EVP_PKEY_verify_init(ctx), ==, 1);

        if (sign_algo == TLS_SIGN_ALGO_PKCS1V15) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING_SIZE), ==, 1);
        } else if (sign_algo == TLS_SIGN_ALGO_RSAPSS) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), ==, 1);
        } else if (sign_algo == TLS_SIGN_ALGO_ECDSA) {
            // Do nothing.
        } else if (sign_algo == TLS_SIGN_ALGO_ED25519) {
            // Do nothing.
        } else {
            goto end;
        }

        if (hash_algo == HASH_SHA1) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1()), ==, 1);
        } else if (hash_algo == HASH_SHA224) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha224()), ==, 1);
        } else if (hash_algo == HASH_SHA256) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()), ==, 1);
        } else if (hash_algo == HASH_SHA384) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384()), ==, 1);
        } else if (hash_algo == HASH_SHA512) {
            PUMP_DEBUG_COND_CHECK(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()), ==, 1);
        } else {
            goto end;
        }

        ret = EVP_PKEY_verify(
                ctx, 
                (const uint8_t*)sign.data(), 
                sign.size(), 
                (const uint8_t*)msg.data(), 
                msg.size()) == 1;

      end:
        if (ctx != nullptr) {
            EVP_PKEY_CTX_free(ctx);
        }
#endif
        return ret;
    }

}  // namespace ssl
}  // namespace pump