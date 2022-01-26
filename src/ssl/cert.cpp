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
#else
        void *key;
        void *cert;
#endif
    };

    x509_certificate* generate_x509_certificate(signature_scheme scheme) {
        PUMP_DEBUG_LOG("generate x509 certificate with signature scheme %d", scheme);
        x509_certificate *xcert = nullptr;

#if defined(PUMP_HAVE_OPENSSL)
        if ((xcert = object_create<x509_certificate>()) == nullptr) {
            PUMP_ERR_LOG("new x509_certificate object failed");
            return nullptr;
        }

        bool ret = false;

        switch (scheme) {
        case TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256:
        case TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384:
        case TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512:
            {
                int32_t ec_nid = -1;
                const EVP_MD *(*new_md_fn)() = nullptr;
                if (scheme == TLS_SIGN_SCHE_ECDSAWITHP256AndSHA256) {
                    new_md_fn = EVP_sha256;
                    ec_nid = NID_X9_62_prime256v1;
                } else if (scheme == TLS_SIGN_SCHE_ECDSAWITHP384AndSHA384) {
                    new_md_fn = EVP_sha384;
                    ec_nid = NID_secp384r1;
                } else if (scheme == TLS_SIGN_SCHE_ECDSAWITHP521AndSHA512) {
                    new_md_fn = EVP_sha512;
                    ec_nid = NID_secp521r1;
                } else {
                    PUMP_WARN_LOG("unknown signature scheme");
                    break;
                }

                EC_KEY *eckey = EC_KEY_new_by_curve_name(ec_nid);
                if (eckey == nullptr) {
                    PUMP_WARN_LOG("create ec_key failed");
                    break;
                }
                EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
                if (EC_KEY_generate_key(eckey) != 1) {
                    EC_KEY_free(eckey);
                    break;
                }

                if ((xcert->key = EVP_PKEY_new()) == nullptr) {
                    break;
                } else if (EVP_PKEY_assign_EC_KEY(xcert->key, eckey) != 1) {
                    EC_KEY_free(eckey);
                    break;
                }
                eckey = nullptr;
                
                if ((xcert->cert = X509_new()) == nullptr) {
                    break;
                } else if (X509_set_version(xcert->cert, 3) != 1) {
                    break;
                } else if (ASN1_INTEGER_set(X509_get_serialNumber(xcert->cert), 3) != 1) {
                    break;
                } else if (X509_gmtime_adj(X509_get_notBefore(xcert->cert), 0) == nullptr) {
                    break;
                } else if (X509_gmtime_adj(X509_get_notAfter(xcert->cert), 365L * 86400) == nullptr) {
                    break;
                } else if (X509_set_pubkey(xcert->cert, xcert->key) != 1) {
                    break;
                }

                X509_NAME *name = X509_get_subject_name(xcert->cert);
                if (name == nullptr) {
                    break;
                } else if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (uint8_t*)"CA", -1, -1, 0) != 1) {
                    break;
                } else if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (uint8_t*)"MyCompany Inc.", -1, -1, 0) != 1) {
                    break;
                } else if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (uint8_t*)"localhost", -1, -1, 0) != 1) {
                    break;
                } else if (X509_set_issuer_name(xcert->cert, name) != 1) {
                    break;
                } else if (X509_sign(xcert->cert, xcert->key, new_md_fn()) == 0) {
                    break;
                }
                
                ret = true;
                
                break;
            }
        default:
            break;
        }

        if (!ret) {
            if (xcert->cert != nullptr){
                X509_free(xcert->cert);
            }
            if (xcert->key != nullptr) {
               EVP_PKEY_free(xcert->key); 
            }
            object_delete(xcert);
            xcert = nullptr;
        }
#endif
        return xcert;
    }

    bool to_x509_certificate_pem(x509_certificate *xcert, std::string &pem) {
        bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio != nullptr) {
            if (PEM_write_bio_X509(bio, xcert->cert) == 1) {
                BUF_MEM *buf = nullptr;
                BIO_get_mem_ptr(bio, &buf);
                pem.assign(buf->data, buf->length);
                ret = true;
            }
            BIO_free(bio);
        }
#endif
        return ret;
    }

    bool to_x509_certificate_bin(x509_certificate *xcert, std::string &bin) {
        bool ret = false;
#if defined(PUMP_HAVE_OPENSSL)
        int32_t size = i2d_X509(xcert->cert, nullptr);
        if (size > 0) {
            bin.resize(size);
            uint8_t *p = (uint8_t*)bin.data();
            if (i2d_X509(xcert->cert, &p) == size) {
                ret = true;
            }
        }
#endif
        return ret;
    }

    x509_certificate* load_x509_certificate_by_pem(
        const std::string &cert, 
        const std::string &key) {
        return load_x509_certificate_by_pem(
            cert.data(), 
            cert.size(),
            key.data(), 
            key.size());
    }

    x509_certificate* load_x509_certificate_by_pem(
        const block_t *cert, 
        int32_t cert_size,
        const block_t *key, 
        int32_t key_size) {
        x509_certificate *xcert = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        if ((xcert = object_create<x509_certificate>()) == nullptr) {
            PUMP_ERR_LOG("new x509_certificate object failed");
            return nullptr;
        }
 
        bool ret = false;
        BIO *bio = nullptr;

        do
        {
            if ((bio = BIO_new_mem_buf(cert, cert_size)) == nullptr) {
                break;
            }
            xcert->cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
            if (xcert->cert == nullptr) {
                break;
            }

            if (key_size > 0) {
                BIO_free(bio);
                if ((bio = BIO_new_mem_buf(key, key_size)) == nullptr) {
                    break;
                }
                xcert->key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
                if (xcert->key == nullptr) {
                    break;
                }
            }

            ret = true;

        } while (false);

        if (bio) {
            BIO_free(bio);
        }

        if (!ret) {
            if (xcert->cert != nullptr){
                X509_free(xcert->cert);
            }
            if (xcert->key != nullptr) {
               EVP_PKEY_free(xcert->key); 
            }
            object_delete(xcert);
            xcert = nullptr;
        }
#endif
        return xcert;
    }

    x509_certificate* load_x509_certificate_by_bin(
        const std::string &cert,
        const std::string &key) {
        return load_x509_certificate_by_bin(
            cert.data(), 
            cert.size(),
            key.data(),
            key.size());
    }

    x509_certificate* load_x509_certificate_by_bin(
        const block_t *cert, 
        int32_t cert_size,
        const block_t *key, 
        int32_t key_size) {
        x509_certificate *xcert = nullptr;
#if defined(PUMP_HAVE_OPENSSL)
        if ((xcert = object_create<x509_certificate>()) == nullptr) {
            PUMP_ERR_LOG("new x509_certificate object failed");
            return nullptr;
        }

        bool ret = false;

        do
        {
            xcert->cert = d2i_X509(nullptr, (const uint8_t**)&cert, cert_size);
            if (xcert->cert == nullptr) {
                break;
            }

            if (key_size > 0) {
                xcert->key = d2i_AutoPrivateKey(nullptr, (const uint8_t**)&key, key_size);
                if (xcert->key == nullptr) {
                    break;
                }
            }

            ret = true;

        } while (false);

        if (!ret) {
            if (xcert->cert != nullptr){
                X509_free(xcert->cert);
            }
            if (xcert->key != nullptr) {
               EVP_PKEY_free(xcert->key); 
            }
            object_delete(xcert);
            xcert = nullptr;
        }
#endif
        return xcert;
    }

    void free_x509_certificate(x509_certificate *xcert) {
        if (xcert == nullptr) {
            return;
        }
#if defined(PUMP_HAVE_OPENSSL)
        if (xcert->cert) {
            X509_free(xcert->cert);
        }
        if (xcert->key) {
            EVP_PKEY_free(xcert->key);
        }
#endif
        object_delete(xcert);
    }

    bool verify_x509_certificates(std::vector<x509_certificate*> &xcerts) {
#if defined(PUMP_HAVE_OPENSSL)
        X509_STORE *store = X509_STORE_new();
        if (store == nullptr) {
            return false;
        }
        for (int32_t i = 1; i < (int32_t)xcerts.size(); i++) {
            if (X509_STORE_add_cert(store, xcerts[i]->cert) != 1) {
                X509_STORE_free(store);
                return false;
            }
        }

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        if (ctx == nullptr) {
            X509_STORE_free(store);
            return false;
        } else if (X509_STORE_CTX_init(ctx, store, xcerts[0]->cert, nullptr) != 1) {
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            return false;
        }

        bool success = true;
        if (X509_verify_cert(ctx) != 1) {
            int32_t ec = X509_STORE_CTX_get_error(ctx);
            if (ec != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
                success = false;
            }
        }

        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);

        return success;
#else
        return false;
#endif
    }

    bool has_x509_scts(x509_certificate *xcert) {
#if defined(PUMP_HAVE_OPENSSL)
        if (X509_get_ext_by_NID(xcert->cert, NID_ct_precert_scts, -1) >= 0) {
            return true;
        }
#endif
        return false;
    }

    bool get_x509_scts(x509_certificate *xcert, std::vector<std::string> &scts) {
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
                BUF_MEM *buf = nullptr;
                BIO_get_mem_ptr(bio, &buf);
                scts.push_back(buf->data);
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
            {
                scheme = TLS_SIGN_SCHE_ED25519;
                break;
            }
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
#if defined(PUMP_HAVE_OPENSSL)
        size_t sign_len = 0;
        PUMP_ASSERT(xcert->key != nullptr);
        if (xcert->key == nullptr) {
            return false;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(xcert->key, nullptr);
        if (ctx == nullptr) {
            return false;
        } 
        
        do 
        {
            if (EVP_PKEY_sign_init(ctx) != 1) {
                break;
            }

            if (sign_algo == TLS_SIGN_ALGO_PKCS1V15) {
                if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING_SIZE) != 1) {
                    break;
                }
            } else if (sign_algo == TLS_SIGN_ALGO_RSAPSS) {
                if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1) {
                    break;
                }
            } else if (sign_algo == TLS_SIGN_ALGO_ECDSA) {
                // Do nothing.
            } else if (sign_algo == TLS_SIGN_ALGO_ED25519) {
                // Do nothing.
            } else {
                break;
            }

            if (hash_algo == HASH_SHA1) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1()) != 1) {
                    break;
                }
            } else if (hash_algo == HASH_SHA224) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha224()) != 1) {
                    break;
                }
            } else if (hash_algo == HASH_SHA256) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) != 1) {
                    break;
                }
            } else if (hash_algo == HASH_SHA384) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384()) != 1) {
                    break;
                }
            } else if (hash_algo == HASH_SHA512) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()) != 1) {
                    break;
                }
            } else {
                break;
            }

            if (EVP_PKEY_sign(ctx, nullptr, &sign_len, (const uint8_t*)msg.data(), msg.size()) != 1) {
                break;
            }
            sign.resize(sign_len);
            if (EVP_PKEY_sign(ctx, (uint8_t*)sign.data(), &sign_len, (const uint8_t*)msg.data(), msg.size()) != 1) {
                break;
            }
            sign.resize(sign_len);

            ret = true;

        } while (false);
        
        EVP_PKEY_CTX_free(ctx);
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
            return false;
        }

        do
        {
            if (EVP_PKEY_verify_init(ctx) != 1) {
                break;
            }

            if (sign_algo == TLS_SIGN_ALGO_PKCS1V15) {
                if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING_SIZE) != 1) {
                    break;
                }
            } else if (sign_algo == TLS_SIGN_ALGO_RSAPSS) {
                if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1) {
                    break;
                }
            } else if (sign_algo == TLS_SIGN_ALGO_ECDSA) {
                // Do nothing.
            } else if (sign_algo == TLS_SIGN_ALGO_ED25519) {
                // Do nothing.
            } else {
                break;
            }

            if (hash_algo == HASH_SHA1) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1()) != 1) {
                    break;
                }
            } else if (hash_algo == HASH_SHA224) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha224()) != 1) {
                    break;
                }
            } else if (hash_algo == HASH_SHA256) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) != 1) {
                    break;
                }
            } else if (hash_algo == HASH_SHA384) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384()) != 1) {
                    break;
                }
            } else if (hash_algo == HASH_SHA512) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha512()) != 1) {
                    break;
                }
            } else {
                break;
            }

            if (EVP_PKEY_verify(
                ctx, 
                (const uint8_t*)sign.data(), 
                sign.size(), 
                (const uint8_t*)msg.data(), 
                msg.size()) == 1) {
                ret = true;
            }
        } while (false);

        EVP_PKEY_CTX_free(ctx);
#endif
        return ret;
    }

}  // namespace ssl
}  // namespace pump